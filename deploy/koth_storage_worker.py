"""SQLite operations executed by kubectl exec, never by the host controller.

stdout is a private framed snapshot for backup, JSON metadata otherwise.
No caller-supplied SQL, archive filenames, credentials, or host database paths.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import stat
import sys
import time
import uuid
import koth_storage_artifacts as artifacts

VERSION = 1
MAX_HEADER = 65536
MAX_DATABASE = 512 * 1024 * 1024
MAX_TOTAL = 10 * 1024 ** 3
IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*\Z")
GAMES = {"jenga", "card-battle-arena", "grand-tour-duel", "dependency-hell", "pixel-smuggler", "swanopoly"}


class StorageError(Exception):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def file_digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def validate_request(request):
    required = {"format_version", "action", "game", "operation_id", "expected_pod_name", "data_root", "store_specs"}
    if set(request) - {'artifact_bundle'} != required or type(request.get('artifact_bundle', False)) is not bool or request["format_version"] != VERSION or request["game"] not in GAMES:
        raise StorageError("INVALID_REQUEST")
    if request["action"] not in {"inspect", "backup", "verify", "restore", "rebase", "revoke_sessions", "cleanup", "artifact_meta", "artifact_backup", "artifact_verify", "artifact_restore", "artifact_rebase", "artifact_check"}:
        raise StorageError("INVALID_REQUEST")
    if str(uuid.UUID(request["operation_id"])) != request["operation_id"]:
        raise StorageError("INVALID_REQUEST")
    if (not os.environ.get("KUBERNETES_SERVICE_HOST")
            or socket.gethostname() != request["expected_pod_name"]):
        raise StorageError("NOT_IN_EXPECTED_POD")
    if request["data_root"] not in {"/data", "/var/lib/koth"}:
        raise StorageError("DATABASE_PATH_UNSAFE")
    specs = request["store_specs"]
    if (not isinstance(specs, list) or not 1 <= len(specs) <= 2
            or len({s.get("store_id") for s in specs}) != len(specs)):
        raise StorageError("INVALID_REQUEST")
    for spec in specs:
        if (set(spec) != {"store_id", "path_env", "default_path", "suffix", "auth_key_table", "session_tables", "immutable_tables"}
                or spec["store_id"] not in {"game", "auth"}
                or spec["auth_key_table"] is not None and not IDENTIFIER.fullmatch(spec["auth_key_table"])
                or not all(IDENTIFIER.fullmatch(s) for s in spec["session_tables"] + spec["immutable_tables"])):
            raise StorageError("INVALID_REQUEST")
    return request


def safe_path(path, root, *, must_exist=True):
    path, root = Path(path), Path(root)
    if not path.is_absolute() or path == root or not path.is_relative_to(root):
        raise StorageError("DATABASE_PATH_UNSAFE")
    for part in [root, *path.parents, path]:
        if part.is_symlink():
            raise StorageError("DATABASE_PATH_UNSAFE")
    if must_exist and (not path.is_file() or not stat.S_ISREG(path.stat().st_mode)):
        raise StorageError("DATABASE_MISSING")
    if not path.resolve().is_relative_to(root.resolve()):
        raise StorageError("DATABASE_PATH_UNSAFE")
    return path


def resolve_stores(request, *, existing=True):
    stores = []
    for spec in request["store_specs"]:
        raw = os.environ.get(spec["path_env"], spec["default_path"])
        path = Path(raw + spec["suffix"])
        stores.append({**spec, "path": safe_path(path, request["data_root"], must_exist=existing)})
    return stores


def check_handles(paths, *, reject_live=False, proc=Path("/proc")):
    targets = {str(p) for p in paths}
    names = targets | {p + s for p in targets for s in ("-wal", "-shm", "-journal")}
    for process in proc.iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            files = list((process / "fd").iterdir())
        except (PermissionError, FileNotFoundError):
            continue
        for file in files:
            try:
                target = os.readlink(file)
            except OSError:
                continue
            if target.removesuffix(" (deleted)") not in names:
                continue
            if target.endswith(" (deleted)"):
                raise StorageError("LIVE_SQLITE_HANDLE_DELETED")
            if reject_live:
                raise StorageError("RESTORE_TARGET_IN_USE")


def connect(path, *, writable=False):
    db = sqlite3.connect(Path(path).as_uri() + ("?mode=rw" if writable else "?mode=ro"), uri=True, timeout=5)
    db.execute("PRAGMA trusted_schema=OFF")
    return db


def normalize(value):
    if isinstance(value, bytes):
        return {"blob_hex": value.hex()}
    return value


def rows_digest(db, table):
    rows = [hashlib.sha256(canonical([normalize(v) for v in row])).hexdigest()
            for row in db.execute('SELECT * FROM "' + table + '"')]
    return hashlib.sha256('\n'.join(sorted(rows)).encode()).hexdigest()


def metadata(path, spec, *, closed_snapshot=False):
    with closing(connect(path)) as db:
        db.execute("BEGIN")
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise StorageError("DATABASE_INTEGRITY_FAILED")
        schema = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        if not all(IDENTIFIER.fullmatch(table) for table in tables):
            raise StorageError("DATABASE_SCHEMA_UNSUPPORTED")
        auth = spec["auth_key_table"]
        if auth and (auth not in tables or db.execute('SELECT count(*) FROM "' + auth + '"').fetchone()[0] == 0):
            raise StorageError("AUTH_HISTORY_MISSING")
        excluded = set(spec["session_tables"]) | {auth}
        hashes = {table: rows_digest(db, table) for table in tables if table not in excluded}
        result = {"store_id": spec["store_id"], "engine": "sqlite",
                "database_path": str(spec.get("path", path)),
                "schema_sha256": hashlib.sha256(canonical(schema)).hexdigest(),
                "business_sha256": hashlib.sha256(canonical(hashes)).hexdigest(),
                "auth_history_sha256": rows_digest(db, auth) if auth else None,
                "table_row_counts": {table: db.execute('SELECT count(*) FROM "' + table + '"').fetchone()[0] for table in tables},
                "sqlite_version": sqlite3.sqlite_version}
        if closed_snapshot:
            result.update(database_bytes=Path(path).stat().st_size, database_sha256=file_digest(path))
        return result


def backup_database(source, destination, deadline):
    def progress(*_):
        if time.monotonic() > deadline:
            raise StorageError("DATABASE_BACKUP_TIMEOUT")
    with closing(connect(source)) as reader, closing(sqlite3.connect(destination)) as target:
        reader.backup(target, pages=256, progress=progress, sleep=0.02)
        # Only the private, completed snapshot is checkpointed or changed.
        target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        target.execute("PRAGMA journal_mode=DELETE")
    with Path(destination).open("rb") as stream:
        os.fsync(stream.fileno())


def private_directory(path, *, create=False):
    if create:path.mkdir(mode=0o700,exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        # A PVC fsGroup remount can add group bits to an owned 0700 directory.
        # Narrow that known group-only mode, never adopt foreign/world access.
        if (info.st_uid != os.geteuid() or info.st_mode & 0o007
                or info.st_mode & 0o070 and info.st_gid not in {os.getegid(),*os.getgroups()}):
            raise StorageError("SCRATCH_PERMISSIONS_INVALID")
        os.fchmod(fd, 0o700); os.fsync(fd)
    finally:
        os.close(fd)
    return path


def scratch_root(request):
    return safe_path(Path(request['data_root'])/('.msgctf-storage-'+str(os.geteuid())),request['data_root'],must_exist=False)


def stage_directory(request):
    # Source exec may use UID 0 while the maintenance Pod uses UID 10001.
    # Each context owns its private parent and never adopts another UID's path.
    parent=private_directory(scratch_root(request),create=True)
    path = parent / (request["operation_id"] + "-" + request["action"])
    path.mkdir(mode=0o700)
    return path


def cleanup_stage(path):
    for file in path.iterdir():
        if file.is_dir() and not file.is_symlink() and re.fullmatch(r'candidate-files-[a-z0-9_]+',file.name):
            count=0
            for folder,dirs,files in os.walk(file,followlinks=False):
                for name in [*dirs,*files]:
                    item=Path(folder)/name;info=item.lstat();count+=1
                    if count>1600000 or stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink==1):
                        raise StorageError('SCRATCH_CONTENT_UNEXPECTED')
            shutil.rmtree(file);continue
        if file.is_symlink() or not file.is_file() or not re.fullmatch(r"(?:backup|authority|candidate)-(?:(?:game|auth)\.sqlite(?:-wal|-shm|-journal)?|artifacts\.(?:pack|part))", file.name):
            raise StorageError("SCRATCH_CONTENT_UNEXPECTED")
        file.unlink()
    path.rmdir()


def write_all(stream, data):
    """Raw unbuffered Pod stdout may legally accept only part of a write."""
    remaining = memoryview(data)
    while remaining:
        count = stream.write(remaining)
        if type(count) is not int or not 0 < count <= len(remaining):
            raise StorageError('OUTPUT_WRITE_INCOMPLETE')
        remaining = remaining[count:]


def write_bundle(stream, header, files):
    line = canonical(header) + b"\n"
    if len(line) > MAX_HEADER:
        raise StorageError("INVALID_BUNDLE")
    write_all(stream, line)
    for file in files:
        with Path(file).open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                write_all(stream, block)
    stream.flush()


def read_bundle(stream, stage, specs, game, prefix, with_artifacts=False):
    line = stream.readline(MAX_HEADER + 1)
    if len(line) > MAX_HEADER or not line.endswith(b"\n"):
        raise StorageError("INVALID_BUNDLE")
    header = json.loads(line)
    if header.get("format_version") != VERSION or header.get("game") != game or not isinstance(header.get("stores"), list):
        raise StorageError("INVALID_BUNDLE")
    items = header["stores"]
    if [v.get("store_id") for v in items] != [s["store_id"] for s in specs] + (['artifacts'] if with_artifacts else []):
        raise StorageError("INVALID_BUNDLE")
    total, files = 0, {}
    for item in items:
        count = item.get("database_bytes")
        is_files = item.get('store_id') == 'artifacts'
        valid = item.get('engine') == ('file_bundle' if is_files else 'sqlite') and type(count) is int and (1 <= count <= artifacts.MAX_PACK if is_files else 512 <= count <= MAX_DATABASE)
        if not valid or not re.fullmatch(r"[0-9a-f]{64}", item.get("database_sha256", "")):
            raise StorageError("INVALID_BUNDLE")
        total += count
        if total > MAX_TOTAL:
            raise StorageError("INVALID_BUNDLE")
        target = stage / (prefix + "-" + item["store_id"] + ('.pack' if is_files else '.sqlite'))
        with target.open("xb") as output:
            remaining = count
            while remaining:
                block = stream.read(min(remaining, 1024 * 1024))
                if not block:
                    raise StorageError("BUNDLE_TRUNCATED")
                output.write(block); remaining -= len(block)
        if file_digest(target) != item["database_sha256"]:
            raise StorageError("BUNDLE_HASH_MISMATCH")
        files[item["store_id"]] = target
    return header, files


def restore_database(snapshot, authority, target, spec, *, rebase=False):
    original = metadata(snapshot, spec, closed_snapshot=True)
    current = metadata(authority, spec, closed_snapshot=True)
    if original["schema_sha256"] != current["schema_sha256"]:
        raise StorageError("DATABASE_SCHEMA_CHANGED")
    auth = spec["auth_key_table"]
    # The candidate is private. No live database is opened writable or replaced.
    with closing(connect(snapshot, writable=True)) as candidate, closing(connect(authority)) as authority_db:
        candidate.execute("BEGIN IMMEDIATE")
        for table in spec["session_tables"]:
            if candidate.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                candidate.execute('DELETE FROM "' + table + '"')
        if auth:
            columns = [row[1] for row in authority_db.execute('PRAGMA table_info("' + auth + '")')]
            rows = authority_db.execute('SELECT * FROM "' + auth + '"').fetchall()
            candidate.execute('DELETE FROM "' + auth + '"')
            candidate.executemany('INSERT INTO "' + auth + '" VALUES(' + ','.join('?' for _ in columns) + ')', rows)
        candidate.commit()
    result = metadata(snapshot, spec, closed_snapshot=True)
    if (result["business_sha256"] != original["business_sha256"] or result["auth_history_sha256"] != current["auth_history_sha256"]
            or any(result['table_row_counts'].get(t, 0) for t in spec['session_tables'])):
        raise StorageError("RESTORE_VERIFICATION_FAILED")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not rebase:
        raise StorageError("RESTORE_TARGET_NOT_EMPTY")
    if rebase:
        if metadata(target,spec)['schema_sha256']!=current['schema_sha256']:
            raise StorageError('DATABASE_SCHEMA_CHANGED')
        check_handles([target],reject_live=True)
        for item in [target,*(Path(str(target)+suffix) for suffix in ('-wal','-shm','-journal'))]:
            if item.exists() or item.is_symlink():
                info=item.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid():
                    raise StorageError('OFFLINE_REBASE_TARGET_UNSAFE')
                if item!=target:item.unlink()
    os.chmod(snapshot, 0o600)
    os.replace(snapshot, target)
    with target.open("rb") as stream:
        os.fsync(stream.fileno())
    directory=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)
    return result


def run(request, input_stream, output_stream):
    os.umask(0o077)
    validate_request(request)
    stores = resolve_stores(request, existing=request["action"] not in {"restore", "cleanup"})
    check_handles([s["path"] for s in stores], reject_live=request["action"] in {"restore", "rebase", "revoke_sessions"})
    if request['action'] == 'artifact_meta':
        write_all(output_stream, canonical({'artifact_roots': artifacts.roots(request['game'], request['data_root'])})); return
    if request['action'] == 'cleanup':
        removed = []
        parents=[scratch_root(request)]
        legacy=safe_path(Path(request['data_root'])/'.msgctf-storage',request['data_root'],must_exist=False)
        if legacy.exists() and legacy.stat().st_uid==os.geteuid():parents.append(legacy)
        for parent in parents:
            if not parent.exists():continue
            private_directory(parent)
            for action in ('backup', 'verify', 'restore', 'rebase', 'revoke_sessions', 'artifact_backup', 'artifact_verify', 'artifact_restore', 'artifact_rebase', 'artifact_check'):
                folder = safe_path(parent / (request['operation_id'] + '-' + action), request['data_root'], must_exist=False)
                if folder.exists():
                    private_directory(folder)
                    check_handles(list(folder.iterdir()), reject_live=True)
                    cleanup_stage(folder); removed.append(action)
        write_all(output_stream, canonical({'removed_scratch_actions': removed})); return
    if request["action"] == "inspect":
        result = {"format_version": VERSION, "game": request["game"], "sqlite_context": "service_pod",
                  "stores": [metadata(s["path"], s) for s in stores], "deleted_sqlite_handle_count": 0}
        write_all(output_stream, canonical(result)); return
    stage = stage_directory(request)
    try:
        if request['action'].startswith('artifact_'):
            root_map = artifacts.roots(request['game'], request['data_root'])
            line = input_stream.readline(artifacts.MAX_INDEX + 1)
            if len(line) > artifacts.MAX_INDEX or not line.endswith(b'\n'):
                raise StorageError('ARTIFACT_REFERENCE_LIMIT')
            expected = json.loads(line)
            if not isinstance(expected, dict) or set(expected) != {'references'} or request['game'] != 'dependency-hell':
                raise StorageError('INVALID_REQUEST')
            refs = artifacts.dependency_references(expected['references'], root_map['artifacts'])
            if request['action'] == 'artifact_backup':
                if input_stream.read(1): raise StorageError('INVALID_BUNDLE')
                path = stage / 'backup-artifacts.pack'
                info = artifacts.pack(path, refs, root_map)
                info['database_references_sha256'] = hashlib.sha256(canonical(expected['references'])).hexdigest()
                write_bundle(output_stream, {'format_version': VERSION, 'game': request['game'], 'stores': [info]}, [path])
            elif request['action'] == 'artifact_check':
                if input_stream.read(1): raise StorageError('INVALID_BUNDLE')
                write_all(output_stream, canonical(artifacts.check_sources(refs, root_map)))
            else:
                header, files = read_bundle(input_stream, stage, [], request['game'], 'backup', with_artifacts=True)
                if input_stream.read(1): raise StorageError('INVALID_BUNDLE')
                if header['stores'][0]['artifact_roots'] != root_map:
                    raise StorageError('ARTIFACT_ROOT_SCOPE_CHANGED')
                proof = artifacts.rebase_pack(files['artifacts'],refs,root_map) if request['action']=='artifact_rebase' else artifacts.check_pack(files['artifacts'], refs, root_map, restore=request['action']=='artifact_restore')
                artifacts.check_metadata(header['stores'][0], refs, proof)
                if request['action']=='artifact_restore': artifacts.check_sources(refs, root_map)
                write_all(output_stream, canonical(proof))
            return
        if request["action"] == "backup":
            files, info = [], []
            for spec in stores:
                path = stage / ("backup-" + spec["store_id"] + ".sqlite")
                backup_database(spec["path"], path, time.monotonic() + 45)
                info.append(metadata(path, spec, closed_snapshot=True)); files.append(path)
            if request.get('artifact_bundle'):
                if request['game'] != 'grand-tour-duel': raise StorageError('INVALID_REQUEST')
                with closing(connect(files[0])) as db:
                    refs = artifacts.grand_references(db)
                path = stage / 'backup-artifacts.pack'
                info.append(artifacts.pack(path, refs, artifacts.roots(request['game'], request['data_root']))); files.append(path)
            write_bundle(output_stream, {"format_version": VERSION, "game": request["game"], "stores": info}, files)
        else:
            header, files = read_bundle(input_stream, stage, stores, request["game"], "backup", with_artifacts=request.get('artifact_bundle', False))
            if request['action'] == 'revoke_sessions':
                if input_stream.read(1): raise StorageError('INVALID_BUNDLE')
                results = []
                for spec in stores:
                    before = metadata(spec['path'], spec)
                    active = metadata(files[spec['store_id']], spec)
                    if before['schema_sha256'] != active['schema_sha256']:
                        raise StorageError('DATABASE_SCHEMA_CHANGED')
                    with closing(connect(spec['path'], writable=True)) as db, closing(connect(files[spec['store_id']])) as authority_db:
                        db.execute('BEGIN IMMEDIATE')
                        for table in spec['session_tables']:
                            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                                db.execute('DELETE FROM "' + table + '"')
                        auth = spec['auth_key_table']
                        if auth:
                            rows = authority_db.execute('SELECT * FROM "' + auth + '"').fetchall()
                            columns = authority_db.execute('PRAGMA table_info("' + auth + '")').fetchall()
                            db.execute('DELETE FROM "' + auth + '"')
                            db.executemany('INSERT INTO "' + auth + '" VALUES(' + ','.join('?' for _ in columns) + ')', rows)
                        db.commit()
                    after = metadata(spec['path'], spec)
                    if (after['business_sha256'] != before['business_sha256'] or after['auth_history_sha256'] != active['auth_history_sha256']
                            or any(after['table_row_counts'].get(t, 0) for t in spec['session_tables'])):
                        raise StorageError('RESTORE_VERIFICATION_FAILED')
                    results.append(after)
                result = {'stores': results, 'current_auth_history_preserved': True, 'restored_session_row_count': 0}
                write_all(output_stream, canonical(result))
            elif request["action"] == "verify":
                if input_stream.read(1):
                    raise StorageError('INVALID_BUNDLE')
                results = []
                for spec in stores:
                    with closing(connect(spec["path"])) as live:
                        live.execute("ATTACH DATABASE ? AS snapshot", (files[spec["store_id"]].as_uri() + "?mode=ro",))
                        counts = {}
                        for table in spec["immutable_tables"]:
                            if not live.execute("SELECT 1 FROM snapshot.sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                                raise StorageError("DATABASE_SCHEMA_CHANGED")
                            missing = live.execute('SELECT count(*) FROM(SELECT * FROM snapshot."' + table + '" EXCEPT SELECT * FROM main."' + table + '")').fetchone()[0]
                            if missing:
                                raise StorageError("ORIGINAL_ROWS_CHANGED")
                            counts[table] = missing
                        results.append({"store_id": spec["store_id"], "missing_or_changed_row_counts": counts})
                result = {"game": request["game"], "sqlite_context": "service_pod", "stores": results}
                if request.get('artifact_bundle'):
                    with closing(connect(files['game'])) as db: refs = artifacts.grand_references(db)
                    root_map = artifacts.roots(request['game'], request['data_root'])
                    if header['stores'][-1]['artifact_roots'] != root_map: raise StorageError('ARTIFACT_ROOT_SCOPE_CHANGED')
                    result['artifacts'] = artifacts.check_pack(files['artifacts'], refs, root_map, check_live=True)
                    artifacts.check_metadata(header['stores'][-1], refs, result['artifacts'])
                write_all(output_stream, canonical(result))
            else:
                _, authority = read_bundle(input_stream, stage, stores, request["game"], "authority")
                if input_stream.read(1):
                    raise StorageError("INVALID_BUNDLE")
                rebased=None
                if request['action']=='rebase' and request.get('artifact_bundle'):
                    with closing(connect(files['game'])) as db:refs=artifacts.grand_references(db)
                    root_map=artifacts.roots(request['game'],request['data_root'])
                    if header['stores'][-1]['artifact_roots']!=root_map:raise StorageError('ARTIFACT_ROOT_SCOPE_CHANGED')
                    rebased=artifacts.rebase_pack(files['artifacts'],refs,root_map)
                    artifacts.check_metadata(header['stores'][-1],refs,rebased)
                results = [restore_database(files[s["store_id"]], authority[s["store_id"]], s["path"], s,rebase=request['action']=='rebase') for s in stores]
                result = {"game": request["game"], "sqlite_context": "offline_rebase_pod" if request['action']=='rebase' else "isolated_restore_pod", "stores": results,
                          "current_auth_history_preserved": True, "restored_session_row_count": 0}
                if rebased is not None:result['artifacts']=rebased
                elif request.get('artifact_bundle'):
                    with closing(connect(stores[0]['path'])) as db: refs = artifacts.grand_references(db)
                    root_map = artifacts.roots(request['game'], request['data_root'])
                    if header['stores'][-1]['artifact_roots'] != root_map: raise StorageError('ARTIFACT_ROOT_SCOPE_CHANGED')
                    result['artifacts'] = artifacts.check_pack(files['artifacts'], refs, root_map, restore=True)
                    artifacts.check_metadata(header['stores'][-1], refs, result['artifacts'])
                    artifacts.check_sources(refs, root_map)
                write_all(output_stream, canonical(result))
    finally:
        cleanup_stage(stage)


if __name__ == "__main__":
    try:
        run(json.loads(sys.argv[1]), sys.stdin.buffer, sys.stdout.buffer)
    except Exception as error:
        code = str(error) if isinstance(error, (StorageError, artifacts.ArtifactError)) else "STORAGE_WORKER_FAILED"
        sys.stderr.write(json.dumps({"error_code": code}) + "\n")
        raise SystemExit(1) from None
