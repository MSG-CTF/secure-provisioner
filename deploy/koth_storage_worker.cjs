'use strict';
// Executed inside the Swanopoly source/restore Pod. Host code never loads SQLite.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { once } = require('node:events');
const { DatabaseSync, backup } = require('node:sqlite');
const VERSION = 1, MAX_HEADER = 65536, MAX_DATABASE = 512 * 1024 * 1024;
const identifier = /^[a-z_][a-z0-9_]*$/;
const fail = (code) => { const error = new Error(code); error.storageCode = code; throw error; };
const canonical = (value) => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? { integer: String(v) } : v);
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');

function fileDigest(file) {
  const hash = crypto.createHash('sha256'), block = Buffer.alloc(1024 * 1024), fd = fs.openSync(file, 'r');
  try { let count; while ((count = fs.readSync(fd, block)) > 0) hash.update(block.subarray(0, count)); }
  finally { fs.closeSync(fd); }
  return hash.digest('hex');
}

function safePath(file, root, existing = true) {
  const target = path.resolve(file), base = path.resolve(root);
  if (!path.isAbsolute(file) || !target.startsWith(base + '/')) fail('DATABASE_PATH_UNSAFE');
  for (let current = target; current !== '/'; current = path.dirname(current)) {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) fail('DATABASE_PATH_UNSAFE');
  }
  if (existing && (!fs.existsSync(target) || !fs.statSync(target).isFile())) fail('DATABASE_MISSING');
  return target;
}

function validateRequest(request) {
  const required = ['format_version', 'action', 'game', 'operation_id', 'expected_pod_name', 'data_root', 'store_specs'];
  if (Object.keys(request).sort().join() !== required.sort().join() || request.format_version !== VERSION
      || request.game !== 'swanopoly' || !['inspect', 'backup', 'verify', 'restore', 'rebase', 'revoke_sessions', 'cleanup'].includes(request.action)
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(request.operation_id)) fail('INVALID_REQUEST');
  if (!process.env.KUBERNETES_SERVICE_HOST || os.hostname() !== request.expected_pod_name) fail('NOT_IN_EXPECTED_POD');
  if (request.data_root !== '/data' || !Array.isArray(request.store_specs) || request.store_specs.length !== 1) fail('INVALID_REQUEST');
  const spec = request.store_specs[0];
  if (Object.keys(spec).sort().join() !== ['store_id', 'path_env', 'default_path', 'suffix', 'auth_key_table', 'session_tables', 'immutable_tables'].sort().join()
      || spec.store_id !== 'game' || spec.auth_key_table !== 'session_keys'
      || ![...spec.session_tables, ...spec.immutable_tables].every(t => identifier.test(t))) fail('INVALID_REQUEST');
}

function resolveStores(request, existing = true) {
  return request.store_specs.map(spec => {
    let suffix = spec.suffix;
    if (suffix.includes('${KOTH_MATCH_ID}')) {
      const match = process.env.KOTH_MATCH_ID || '';
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(match)) fail('INVALID_MATCH_SCOPE');
      suffix = suffix.replace('${KOTH_MATCH_ID}', match);
    }
    if (suffix.includes('${')) fail('INVALID_REQUEST');
    return { ...spec, path: safePath((process.env[spec.path_env] || spec.default_path) + suffix, request.data_root, existing) };
  });
}

function checkHandles(paths, rejectLive = false, proc = '/proc') {
  const names = new Set(paths.flatMap(p => [p, p + '-wal', p + '-shm', p + '-journal']));
  for (const pid of fs.readdirSync(proc).filter(p => /^\d+$/.test(p) && Number(p) !== process.pid)) {
    let files; try { files = fs.readdirSync(`${proc}/${pid}/fd`); } catch { continue; }
    for (const fd of files) {
      let name; try { name = fs.readlinkSync(`${proc}/${pid}/fd/${fd}`); } catch { continue; }
      if (!names.has(name.replace(/ \(deleted\)$/, ''))) continue;
      if (name.endsWith(' (deleted)')) fail('LIVE_SQLITE_HANDLE_DELETED');
      if (rejectLive) fail('RESTORE_TARGET_IN_USE');
    }
  }
}

function connect(file, writable = false) {
  const db = new DatabaseSync(file, { readOnly: !writable, timeout: 5000 });
  db.exec('PRAGMA trusted_schema=OFF'); return db;
}

function rowsDigest(db, table) {
  const statement = db.prepare(`SELECT * FROM "${table}"`); statement.setReturnArrays(true); statement.setReadBigInts(true);
  const hashes = [];
  for (const row of statement.iterate()) hashes.push(digest(canonical(row.map(v => v instanceof Uint8Array ? { blob_hex: Buffer.from(v).toString('hex') } : v))));
  return digest(hashes.sort().join('\n'));
}

function metadata(file, spec, closedSnapshot = false) {
  const db = connect(file);
  try {
    db.exec('BEGIN');
    if (db.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok') fail('DATABASE_INTEGRITY_FAILED');
    const schemaStatement = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"); schemaStatement.setReturnArrays(true);
    const schema = schemaStatement.all(), tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(r => r.name);
    if (!tables.every(t => identifier.test(t))) fail('DATABASE_SCHEMA_UNSUPPORTED');
    if (!tables.includes(spec.auth_key_table) || !db.prepare(`SELECT count(*) n FROM "${spec.auth_key_table}"`).get().n) fail('AUTH_HISTORY_MISSING');
    const business = Object.fromEntries(tables.filter(t => !spec.session_tables.includes(t) && t !== spec.auth_key_table).map(t => [t, rowsDigest(db, t)]));
    const result = { store_id: spec.store_id, engine: 'sqlite', database_path: spec.path || file,
      schema_sha256: digest(canonical(schema)), business_sha256: digest(canonical(business)),
      auth_history_sha256: rowsDigest(db, spec.auth_key_table), table_row_counts: Object.fromEntries(tables.map(t => [t, db.prepare(`SELECT count(*) n FROM "${t}"`).get().n])),
      sqlite_version: db.prepare('SELECT sqlite_version() version').get().version };
    if (closedSnapshot) Object.assign(result, { database_bytes: fs.statSync(file).size, database_sha256: fileDigest(file) });
    return result;
  } finally { db.close(); }
}

async function backupDatabase(source, destination, deadline) {
  const db = connect(source);
  try { await backup(db, destination, { rate: 256, progress: () => { if (Date.now() > deadline) fail('DATABASE_BACKUP_TIMEOUT'); } }); }
  finally { db.close(); }
  const closed = connect(destination, true);
  try { closed.exec('PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE'); } finally { closed.close(); }
  const fd = fs.openSync(destination, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function privateDirectory(parent, create=false) {
  if (create && !fs.existsSync(parent)) fs.mkdirSync(parent, { mode: 0o700 });
  const fd = fs.openSync(parent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    if (stat.uid !== process.geteuid() || stat.mode & 0o007 || (stat.mode & 0o070) && !new Set([process.getegid(),...process.getgroups()]).has(stat.gid)) fail('SCRATCH_PERMISSIONS_INVALID');
    fs.fchmodSync(fd, 0o700); fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  return parent;
}

function scratchRoot(request) {return safePath(path.join(request.data_root,'.msgctf-storage-'+process.geteuid()),request.data_root,false);}
function stageDirectory(request) {
  const parent=privateDirectory(scratchRoot(request),true);
  const folder = path.join(parent, request.operation_id + '-' + request.action); fs.mkdirSync(folder, { mode: 0o700 }); return folder;
}

function cleanupStage(folder) {
  for (const file of fs.readdirSync(folder)) {
    if (!/^(backup|authority|candidate)-(game|auth)\.sqlite(-wal|-shm|-journal)?$/.test(file) || !fs.lstatSync(path.join(folder, file)).isFile()) fail('SCRATCH_CONTENT_UNEXPECTED');
    fs.unlinkSync(path.join(folder, file));
  }
  fs.rmdirSync(folder);
}

function readLine(fd) {
  const bytes = [], byte = Buffer.alloc(1);
  for (let index = 0; index <= MAX_HEADER; index++) {
    if (fs.readSync(fd, byte) !== 1) fail('BUNDLE_TRUNCATED');
    if (byte[0] === 10) return Buffer.from(bytes).toString('utf8'); bytes.push(byte[0]);
  }
  fail('INVALID_BUNDLE');
}

function writeFileAll(fd, data) {
  let offset = 0;
  while (offset < data.length) {
    const count = fs.writeSync(fd, data, offset, data.length - offset);
    if (count <= 0) fail('OUTPUT_WRITE_INCOMPLETE');
    offset += count;
  }
}

function readBundle(fd, folder, specs, game, prefix) {
  const header = JSON.parse(readLine(fd));
  if (header.format_version !== VERSION || header.game !== game || !Array.isArray(header.stores)
      || header.stores.map(s => s.store_id).join() !== specs.map(s => s.store_id).join()) fail('INVALID_BUNDLE');
  const files = {};
  for (const item of header.stores) {
    if (item.engine !== 'sqlite' || !Number.isSafeInteger(item.database_bytes) || item.database_bytes < 512 || item.database_bytes > MAX_DATABASE || !/^[0-9a-f]{64}$/.test(item.database_sha256)) fail('INVALID_BUNDLE');
    const target = path.join(folder, prefix + '-' + item.store_id + '.sqlite'), out = fs.openSync(target, 'wx', 0o600), buffer = Buffer.alloc(1024 * 1024);
    try {
      let remaining = item.database_bytes;
      while (remaining) { const size = fs.readSync(fd, buffer, 0, Math.min(remaining, buffer.length)); if (!size) fail('BUNDLE_TRUNCATED'); writeFileAll(out, buffer.subarray(0, size)); remaining -= size; }
    } finally { fs.closeSync(out); }
    if (fileDigest(target) !== item.database_sha256) fail('BUNDLE_HASH_MISMATCH'); files[item.store_id] = target;
  }
  return { header, files };
}

function restoreDatabase(snapshot, authority, target, spec, rebase = false) {
  const original = metadata(snapshot, spec, true), current = metadata(authority, spec, true);
  if (original.schema_sha256 !== current.schema_sha256) fail('DATABASE_SCHEMA_CHANGED');
  const candidate = connect(snapshot, true), authorityDb = connect(authority);
  try {
    candidate.exec('BEGIN IMMEDIATE');
    for (const table of spec.session_tables) if (candidate.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) candidate.exec(`DELETE FROM "${table}"`);
    const rows = authorityDb.prepare(`SELECT * FROM "${spec.auth_key_table}"`).all(); candidate.exec(`DELETE FROM "${spec.auth_key_table}"`);
    for (const row of rows) candidate.prepare(`INSERT INTO "${spec.auth_key_table}" VALUES(${Object.keys(row).map(() => '?').join(',')})`).run(...Object.values(row));
    candidate.exec('COMMIT');
  } finally { candidate.close(); authorityDb.close(); }
  const result = metadata(snapshot, spec, true);
  if (result.business_sha256 !== original.business_sha256 || result.auth_history_sha256 !== current.auth_history_sha256
      || spec.session_tables.some(t => result.table_row_counts[t])) fail('RESTORE_VERIFICATION_FAILED');
  if (fs.existsSync(target) && !rebase) fail('RESTORE_TARGET_NOT_EMPTY');
  if (rebase) {
    if (metadata(target,spec).schema_sha256 !== current.schema_sha256) fail('DATABASE_SCHEMA_CHANGED');
    checkHandles([target],true);
    for (const item of [target,...['-wal','-shm','-journal'].map(s=>target+s)]) {
      let info; try { info=fs.lstatSync(item); } catch(e) { if(e.code==='ENOENT')continue;throw e; }
      if (!info.isFile() || info.nlink!==1 || info.uid!==process.geteuid()) fail('OFFLINE_REBASE_TARGET_UNSAFE');
      if (item!==target)fs.unlinkSync(item);
    }
  }
  fs.mkdirSync(path.dirname(target), { recursive: true }); fs.chmodSync(snapshot, 0o600); fs.renameSync(snapshot, target);
  const fd = fs.openSync(target, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const directory=fs.openSync(path.dirname(target),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
  return result;
}

async function run(request, inputFd = 0, output = process.stdout) {
  process.umask(0o077); validateRequest(request);
  const stores = resolveStores(request, !['restore', 'cleanup'].includes(request.action)); checkHandles(stores.map(s => s.path), ['restore', 'rebase', 'revoke_sessions'].includes(request.action));
  const json = value => output.write(canonical(value));
  if (request.action === 'cleanup') {
    const removed = [];
    const parents=[scratchRoot(request)],legacy=safePath(path.join(request.data_root,'.msgctf-storage'),request.data_root,false);
    if(fs.existsSync(legacy) && fs.statSync(legacy).uid===process.geteuid())parents.push(legacy);
    for(const parent of parents) {
      if(!fs.existsSync(parent))continue;privateDirectory(parent);
      for (const action of ['backup', 'verify', 'restore', 'rebase', 'revoke_sessions']) {
        const folder = safePath(path.join(parent, request.operation_id + '-' + action), request.data_root, false);
        if (!fs.existsSync(folder)) continue;
        privateDirectory(folder);
        checkHandles(fs.readdirSync(folder).map(p => path.join(folder, p)), true); cleanupStage(folder); removed.push(action);
      }
    }
    return json({ removed_scratch_actions: removed });
  }
  if (request.action === 'inspect') return json({ format_version: VERSION, game: request.game, sqlite_context: 'service_pod', stores: stores.map(s => metadata(s.path, s)), deleted_sqlite_handle_count: 0 });
  const folder = stageDirectory(request);
  try {
    if (request.action === 'backup') {
      const info = [], files = [];
      for (const spec of stores) { const file = path.join(folder, 'backup-' + spec.store_id + '.sqlite'); await backupDatabase(spec.path, file, Date.now() + 45000); info.push(metadata(file, spec, true)); files.push(file); }
      const header = canonical({ format_version: VERSION, game: request.game, stores: info }) + '\n'; if (Buffer.byteLength(header) > MAX_HEADER) fail('INVALID_BUNDLE');
      if (!output.write(header)) await once(output, 'drain');
      for (const file of files) for await (const block of fs.createReadStream(file)) if (!output.write(block)) await once(output, 'drain');
    } else {
      const { files } = readBundle(inputFd, folder, stores, request.game, 'backup');
      if (request.action === 'revoke_sessions') {
        if (fs.readSync(inputFd, Buffer.alloc(1)) !== 0) fail('INVALID_BUNDLE');
        const results = stores.map(spec => {
          const before = metadata(spec.path, spec), active = metadata(files[spec.store_id], spec);
          if (before.schema_sha256 !== active.schema_sha256) fail('DATABASE_SCHEMA_CHANGED');
          const db = connect(spec.path, true);
          try {
            db.prepare('ATTACH DATABASE ? AS authority').run(files[spec.store_id]); db.exec('BEGIN IMMEDIATE');
            for (const table of spec.session_tables) if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) db.exec(`DELETE FROM "${table}"`);
            if (spec.auth_key_table) db.exec(`DELETE FROM "${spec.auth_key_table}"; INSERT INTO "${spec.auth_key_table}" SELECT * FROM authority."${spec.auth_key_table}"`);
            db.exec('COMMIT');
          } finally { db.close(); }
          const after = metadata(spec.path, spec);
          if (after.business_sha256 !== before.business_sha256 || after.auth_history_sha256 !== active.auth_history_sha256 || spec.session_tables.some(t => after.table_row_counts[t])) fail('RESTORE_VERIFICATION_FAILED');
          return after;
        });
        json({ stores: results, current_auth_history_preserved: true, restored_session_row_count: 0 });
      } else if (request.action === 'verify') {
        if (fs.readSync(inputFd, Buffer.alloc(1)) !== 0) fail('INVALID_BUNDLE');
        const results = stores.map(spec => {
          const db = connect(spec.path);
          try {
            db.prepare('ATTACH DATABASE ? AS snapshot').run(files[spec.store_id]); const counts = {};
            for (const table of spec.immutable_tables) { const missing = db.prepare(`SELECT count(*) n FROM(SELECT * FROM snapshot."${table}" EXCEPT SELECT * FROM main."${table}")`).get().n; if (missing) fail('ORIGINAL_ROWS_CHANGED'); counts[table] = missing; }
            return { store_id: spec.store_id, missing_or_changed_row_counts: counts };
          } finally { db.close(); }
        });
        json({ game: request.game, sqlite_context: 'service_pod', stores: results });
      } else {
        const authority = readBundle(inputFd, folder, stores, request.game, 'authority').files;
        if (fs.readSync(inputFd, Buffer.alloc(1)) !== 0) fail('INVALID_BUNDLE');
        const results = stores.map(spec => restoreDatabase(files[spec.store_id], authority[spec.store_id], spec.path, spec,request.action==='rebase'));
        json({ game: request.game, sqlite_context: request.action==='rebase'?'offline_rebase_pod':'isolated_restore_pod', stores: results, current_auth_history_preserved: true, restored_session_row_count: 0 });
      }
    }
  } finally { cleanupStage(folder); }
}

module.exports = { run, metadata, backupDatabase, restoreDatabase, checkHandles, safePath, validateRequest, resolveStores, fileDigest };
if (require.main === module) run(JSON.parse(process.argv[2])).catch(error => { console.error(JSON.stringify({ error_code: error.storageCode || 'STORAGE_WORKER_FAILED' })); process.exitCode = 1; });
