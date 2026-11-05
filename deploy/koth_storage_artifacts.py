"""DB-bound file snapshots; imported only inside a pinned service/restore Pod.

The format is a bounded sequence of JSON records and individual zlib streams.
It never evaluates submissions, invokes artifacts, or extracts archive paths.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import uuid
import zlib

MAX_FILES = 100000
MAX_FILE = 64 * 1024 * 1024
MAX_RAW = 16 * 1024 ** 3
MAX_PACK = 8 * 1024 ** 3
MAX_INDEX = 32 * 1024 ** 2
MAX_RECORD = 4096
COMPONENT = re.compile(r'[A-Za-z0-9_.-]{1,128}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')


class ArtifactError(Exception):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def digest_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def roots(game, data_root):
    data_root = Path(data_root)
    if game == 'grand-tour-duel':
        result = {'sources': os.getenv('KOTH_SUBMISSIONS_DIR', str(data_root / 'submissions')),
                  'replays': os.getenv('KOTH_REPLAYS_DIR', str(data_root / 'replays'))}
    elif game == 'dependency-hell':
        result = {'artifacts': str(Path(os.getenv('DATA_DIR', str(data_root))) / 'artifacts')}
    else:
        raise ArtifactError('ARTIFACT_GAME_UNSUPPORTED')
    for raw in result.values():
        path = Path(raw)
        if not path.is_absolute() or path == data_root or not path.is_relative_to(data_root) or path.resolve() != path:
            raise ArtifactError('ARTIFACT_ROOT_UNSAFE')
        for part in [data_root, *path.parents, path]:
            if part.is_symlink():
                raise ArtifactError('ARTIFACT_ROOT_UNSAFE')
    values = list(result.values())
    if any(Path(a).is_relative_to(Path(b)) for i,a in enumerate(values) for j,b in enumerate(values) if i != j):
        raise ArtifactError('ARTIFACT_ROOT_OVERLAP')
    return result


def references(rows, allowed_roots):
    if not isinstance(rows, list) or len(rows) > MAX_FILES * 4:
        raise ArtifactError('ARTIFACT_REFERENCE_LIMIT')
    found = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'root', 'path', 'sha256', 'size_bytes'}:
            raise ArtifactError('ARTIFACT_REFERENCE_INVALID')
        root, name, h, size = (row[key] for key in ['root', 'path', 'sha256', 'size_bytes'])
        if root not in allowed_roots or not isinstance(name, str) or len(name) > 1024:
            raise ArtifactError('ARTIFACT_REFERENCE_INVALID')
        parts = name.split('/')
        if not 1 <= len(parts) <= 10 or any(part in {'.', '..'} or not COMPONENT.fullmatch(part) for part in parts):
            raise ArtifactError('ARTIFACT_REFERENCE_PATH_UNSAFE')
        if not isinstance(h, str) or not HASH.fullmatch(h) or size is not None and (type(size) is not int or not 1 <= size <= MAX_FILE):
            raise ArtifactError('ARTIFACT_REFERENCE_INVALID')
        if root == 'artifacts' and (len(parts) != 1 or name != h):
            raise ArtifactError('ARTIFACT_REFERENCE_PATH_UNSAFE')
        key = (root, name)
        if key in found and found[key] != row:
            raise ArtifactError('ARTIFACT_REFERENCE_CONFLICT')
        found[key] = dict(row)
    result = [found[key] for key in sorted(found)]
    if len(result) > MAX_FILES or sum(row['size_bytes'] or 0 for row in result) > MAX_RAW:
        raise ArtifactError('ARTIFACT_REFERENCE_LIMIT')
    return result


def reference_hash(refs):
    return hashlib.sha256(canonical(refs)).hexdigest()


def check_metadata(info, refs, proof):
    if (info.get('compression') != 'zlib_per_file_v1' or info.get('reference_count') != len(refs)
            or info.get('references_sha256') != reference_hash(refs) or info.get('uncompressed_bytes') != proof['uncompressed_bytes']):
        raise ArtifactError('ARTIFACT_METADATA_MISMATCH')


def source_chunks(file, size):
    remaining = size
    while remaining:
        block = file.read(min(remaining, 1024 * 1024))
        if not block:
            raise ArtifactError('ARTIFACT_FILE_CHANGED')
        remaining -= len(block)
        yield block
    if file.read(1):
        raise ArtifactError('ARTIFACT_FILE_CHANGED')


def grand_references(db):
    rows = []
    sources = {}
    for team, identifier, path, h, size in db.execute('SELECT team_id,id,source_relpath,sha256,source_size_bytes FROM submissions'):
        if str(uuid.UUID(team)) != team or str(uuid.UUID(identifier)) != identifier or path != str(team) + '/' + str(identifier) + '/bot.py':
            raise ArtifactError('ARTIFACT_REFERENCE_PATH_UNSAFE')
        rows.append({'root': 'sources', 'path': path, 'sha256': h, 'size_bytes': size})
        sources[path] = (h, size)
    for path, h, size in db.execute('SELECT source_relpath,source_sha256,source_size_bytes FROM duel_tick_entries'):
        if sources.get(path) != (h, size): raise ArtifactError('ARTIFACT_REFERENCE_CONFLICT')
        rows.append({'root': 'sources', 'path': path, 'sha256': h, 'size_bytes': size})
    for path, h, status in db.execute('SELECT replay_relpath,replay_sha256,status FROM practice_games'):
        if path is not None or status == 'COMPLETE':
            rows.append({'root': 'replays', 'path': path, 'sha256': h, 'size_bytes': None})
    for path, h in db.execute('SELECT artifact_relpath,sha256 FROM replays'):
        rows.append({'root': 'replays', 'path': path, 'sha256': h, 'size_bytes': None})
    return references(rows, {'sources', 'replays'})


def dependency_references(rows, artifact_root):
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'artifact_path', 'sha256', 'size_bytes'}:
            raise ArtifactError('ARTIFACT_REFERENCE_INVALID')
        if row['artifact_path'] != str(Path(artifact_root) / row['sha256']):
            raise ArtifactError('ARTIFACT_REFERENCE_PATH_UNSAFE')
        result.append({'root': 'artifacts', 'path': row['sha256'], 'sha256': row['sha256'], 'size_bytes': row['size_bytes']})
    return references(result, {'artifacts'})


@contextmanager
def parent_fd(root, relative, create=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for name in Path(root).parts[1:]:
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        for name in relative.split('/')[:-1]:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, relative.split('/')[-1]
    finally:
        os.close(fd)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


@contextmanager
def source_file(root, ref):
    with parent_fd(root, ref['path']) as (directory, name):
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= MAX_FILE:
            raise ArtifactError('ARTIFACT_FILE_UNSAFE')
        if ref['size_bytes'] is not None and before.st_size != ref['size_bytes']:
            raise ArtifactError('ARTIFACT_FILE_SIZE_MISMATCH')
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as file:
            if identity(os.fstat(file.fileno())) != identity(before):
                raise ArtifactError('ARTIFACT_FILE_CHANGED')
            yield file, before.st_size
            after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if identity(before) != identity(after) or identity(before) != identity(os.fstat(file.fileno())):
                raise ArtifactError('ARTIFACT_FILE_CHANGED')


def check_sources(refs, root_map):
    refs = references(refs, root_map)
    count, total = 0, 0
    for ref in refs:
        h = hashlib.sha256()
        with source_file(root_map[ref['root']], ref) as (file, size):
            for block in source_chunks(file, size):
                h.update(block)
        if h.hexdigest() != ref['sha256']:
            raise ArtifactError('ARTIFACT_FILE_HASH_MISMATCH')
        count += 1
        total += size
        if total > MAX_RAW:
            raise ArtifactError('ARTIFACT_REFERENCE_LIMIT')
    return {'file_count': count, 'uncompressed_bytes': total, 'database_file_consistency_verified': True}


def pack(path, refs, root_map):
    refs = references(refs, root_map)
    total = 0
    with Path(path).open('xb') as output:
        os.chmod(path, 0o600)
        output.write(canonical({'format_version': 1, 'reference_count': len(refs), 'references_sha256': reference_hash(refs)}) + b'\n')
        part = Path(path).with_suffix('.part')
        try:
            for ref in refs:
                h = hashlib.sha256()
                compressor = zlib.compressobj(1)
                with part.open('xb') as compressed:
                    os.chmod(part, 0o600)
                    with source_file(root_map[ref['root']], ref) as (file, size):
                        if total + size > MAX_RAW: raise ArtifactError('ARTIFACT_REFERENCE_LIMIT')
                        for block in source_chunks(file, size):
                            h.update(block)
                            compressed.write(compressor.compress(block))
                        compressed.write(compressor.flush())
                if h.hexdigest() != ref['sha256']:
                    raise ArtifactError('ARTIFACT_FILE_HASH_MISMATCH')
                record = {**ref, 'size_bytes': size, 'compressed_bytes': part.stat().st_size}
                output.write(canonical(record) + b'\n')
                with part.open('rb') as compressed:
                    shutil.copyfileobj(compressed, output, 1024 * 1024)
                part.unlink()
                total += size
                if total > MAX_RAW or output.tell() > MAX_PACK:
                    raise ArtifactError('ARTIFACT_REFERENCE_LIMIT')
            output.flush()
            os.fsync(output.fileno())
        finally:
            part.unlink(missing_ok=True)
    return {'store_id': 'artifacts', 'engine': 'file_bundle', 'database_bytes': Path(path).stat().st_size,
            'database_sha256': digest_file(path), 'artifact_roots': root_map, 'reference_count': len(refs),
            'references_sha256': reference_hash(refs), 'uncompressed_bytes': total, 'compression': 'zlib_per_file_v1',
            'database_file_consistency_verified': True}


def line(stream):
    raw = stream.readline(MAX_RECORD + 1)
    if len(raw) > MAX_RECORD or not raw.endswith(b'\n'):
        raise ArtifactError('ARTIFACT_PACK_INVALID')
    return json.loads(raw)


def check_pack(path, refs, root_map, restore=False, check_live=False):
    refs = references(refs, root_map)
    count, total = 0, 0
    if restore:
        for root in root_map.values():
            parent = Path(root).parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if any(part.is_symlink() for part in [parent, *parent.parents]) or Path(root).exists():
                raise ArtifactError('ARTIFACT_RESTORE_TARGET_NOT_EMPTY')
            Path(root).mkdir(mode=0o700)
    with Path(path).open('rb') as stream:
        header = line(stream)
        if header != {'format_version': 1, 'reference_count': len(refs), 'references_sha256': reference_hash(refs)}:
            raise ArtifactError('ARTIFACT_DATABASE_REFERENCES_MISMATCH')
        for ref in refs:
            row = line(stream)
            if not isinstance(row, dict) or set(row) != {'root', 'path', 'sha256', 'size_bytes', 'compressed_bytes'}:
                raise ArtifactError('ARTIFACT_PACK_INVALID')
            if any(row[key] != ref[key] for key in ['root', 'path', 'sha256']):
                raise ArtifactError('ARTIFACT_DATABASE_REFERENCES_MISMATCH')
            size, compressed = row['size_bytes'], row['compressed_bytes']
            if type(size) is not int or not 1 <= size <= MAX_FILE or type(compressed) is not int or not 1 <= compressed <= MAX_FILE + 1024 * 1024:
                raise ArtifactError('ARTIFACT_PACK_INVALID')
            if ref['size_bytes'] is not None and size != ref['size_bytes']:
                raise ArtifactError('ARTIFACT_DATABASE_REFERENCES_MISMATCH')
            total += size
            if total > MAX_RAW:
                raise ArtifactError('ARTIFACT_REFERENCE_LIMIT')
            h, length, decoder, file = hashlib.sha256(), 0, zlib.decompressobj(), None
            directory_scope = parent_fd(root_map[ref['root']], ref['path'], create=True) if restore else None
            try:
                if restore:
                    directory, name = directory_scope.__enter__()
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    file = os.fdopen(fd, 'wb')
                remaining = compressed
                while remaining:
                    block = stream.read(min(65536, remaining))
                    if not block:
                        raise ArtifactError('ARTIFACT_PACK_TRUNCATED')
                    remaining -= len(block)
                    pending = block
                    while pending:
                        raw = decoder.decompress(pending, min(1024 * 1024, size - length + 1))
                        pending = decoder.unconsumed_tail
                        length += len(raw)
                        if length > size or decoder.unused_data:
                            raise ArtifactError('ARTIFACT_PACK_INVALID')
                        h.update(raw)
                        if file:
                            file.write(raw)
                if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or length != size or h.hexdigest() != ref['sha256']:
                    raise ArtifactError('ARTIFACT_FILE_HASH_MISMATCH')
                if file:
                    file.flush()
                    os.fsync(file.fileno())
                    os.fchmod(file.fileno(), 0o400 if ref['root'] == 'artifacts' else 0o600)
            finally:
                if file:
                    file.close()
                if directory_scope:
                    directory_scope.__exit__(None, None, None)
            count += 1
        if stream.read(1):
            raise ArtifactError('ARTIFACT_PACK_TRAILING_BYTES')
    if check_live:
        check_sources(refs, root_map)
    return {'file_count': count, 'uncompressed_bytes': total, 'references_sha256': reference_hash(refs),
            'database_file_consistency_verified': True, 'files_restored': restore, 'live_source_files_verified': check_live}
