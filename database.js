const initSqlJs = require('sql.js');
const bcrypt    = require('bcryptjs');
const path      = require('path');
const fs        = require('fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'xm.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

let _db = null;
let _saveTimer = null;

function scheduleSave() {
  if (_saveTimer) clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => {
    try { fs.writeFileSync(DB_PATH, Buffer.from(_db.export())); } catch(e) {}
  }, 500);
}

function run(sql, params=[]) {
  _db.run(sql, params);
  scheduleSave();
  const res = _db.exec('SELECT last_insert_rowid() as id');
  return { lastID: res[0]?.values[0]?.[0] };
}

function get(sql, params=[]) {
  const res = _db.exec(sql, params);
  if (!res.length || !res[0].values.length) return undefined;
  return Object.fromEntries(res[0].columns.map((c,i)=>[c, res[0].values[0][i]]));
}

function all(sql, params=[]) {
  const res = _db.exec(sql, params);
  if (!res.length) return [];
  return res[0].values.map(row=>Object.fromEntries(res[0].columns.map((c,i)=>[c,row[i]])));
}

async function initSchema() {
  const SQL = await initSqlJs();
  _db = fs.existsSync(DB_PATH) ? new SQL.Database(fs.readFileSync(DB_PATH)) : new SQL.Database();

  run(`PRAGMA foreign_keys = ON`);

  run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  run(`CREATE TABLE IF NOT EXISTS schools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, city TEXT NOT NULL, UNIQUE(name,city)
  )`);

  run(`CREATE TABLE IF NOT EXISTS teachers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    school_id INTEGER,
    class TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  run(`CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    class TEXT NOT NULL,
    grp INTEGER NOT NULL,
    school_id INTEGER NOT NULL,
    academic_year TEXT NOT NULL DEFAULT '2024-25',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  run(`CREATE TABLE IF NOT EXISTS modules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL, subject TEXT NOT NULL, term INTEGER NOT NULL,
    quiz_open INTEGER DEFAULT 1
  )`);

  run(`CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id INTEGER NOT NULL,
    question TEXT NOT NULL,
    option_a TEXT NOT NULL, option_b TEXT NOT NULL,
    option_c TEXT, option_d TEXT,
    correct TEXT NOT NULL,
    marks INTEGER DEFAULT 1,
    time_limit_sec INTEGER DEFAULT 30,
    grp INTEGER DEFAULT 0
  )`);

  run(`CREATE TABLE IF NOT EXISTS quiz_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    module_id INTEGER NOT NULL,
    academic_year TEXT NOT NULL DEFAULT '2024-25',
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME,
    score INTEGER DEFAULT 0,
    max_score INTEGER DEFAULT 0,
    time_sec INTEGER,
    status TEXT DEFAULT 'in_progress',
    UNIQUE(student_id, module_id, academic_year)
  )`);

  run(`CREATE TABLE IF NOT EXISTS quiz_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    answer TEXT,
    correct INTEGER DEFAULT 0,
    time_sec INTEGER
  )`);

  run(`CREATE TABLE IF NOT EXISTS teacher_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL, term INTEGER NOT NULL,
    academic_year TEXT NOT NULL DEFAULT '2024-25',
    comment TEXT NOT NULL,
    UNIQUE(student_id, term, academic_year)
  )`);

  // Seed modules
  const modules = [
    [1,'Our Amazing World','History & Geography',1],
    [2,'Science All Around Us','Science & Nature',1],
    [3,'Leaders Who Changed History','History & Geography',1],
    [4,'India Spotlight','Current Affairs',1],
    [5,'The Living Planet','Science & Nature',1],
    [6,'Sports & Champions','Arts, Culture & Sports',1],
    [7,'World in the News','Current Affairs',2],
    [8,'Inventions That Changed Everything','Science & Nature',2],
    [9,'Cultures & Festivals','Arts, Culture & Sports',2],
    [10,'Maps, Nations & Borders','History & Geography',2],
    [11,'Space & Beyond','Science & Nature',2],
    [12,'Arts, Books & Cinema','Arts, Culture & Sports',2],
  ];
  for (const [id,name,subject,term] of modules)
    run('INSERT OR IGNORE INTO modules (id,name,subject,term) VALUES (?,?,?,?)',[id,name,subject,term]);

  // Seed admin
  if (!get('SELECT id FROM admins WHERE username=?',['admin'])) {
    run('INSERT INTO admins (username,password,name) VALUES (?,?,?)',
      ['admin', bcrypt.hashSync('xmadmin2024',10), 'XM Admin']);
  }

  fs.writeFileSync(DB_PATH, Buffer.from(_db.export()));
  console.log('✅  Database ready');
}

module.exports = { run, get, all, initSchema };
