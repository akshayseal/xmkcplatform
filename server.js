const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const multer  = require('multer');
const { parse } = require('csv-parse/sync');
const path    = require('path');
const fs      = require('fs');

const { run, get, all, initSchema } = require('./database');
const { calcQQ, getBand, SUBJECTS, SUBJECT_COLORS, BANDS } = require('./qq');

const app  = express();
const PORT = process.env.PORT || 3000;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10*1024*1024 } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'xm-platform-secret-2024',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*8 }
}));
app.use(express.static(path.join(__dirname,'public')));

// ── AUTH MIDDLEWARE ────────────────────────────────────────────────────────────
const requireAdmin   = (req,res,next) => req.session.role==='admin'   ? next() : res.status(401).json({error:'Unauthorized'});
const requireTeacher = (req,res,next) => ['admin','teacher'].includes(req.session.role) ? next() : res.status(401).json({error:'Unauthorized'});
const requireStudent = (req,res,next) => req.session.role==='student' ? next() : res.status(401).json({error:'Unauthorized'});
const requireAuth    = (req,res,next) => req.session.userId ? next() : res.status(401).json({error:'Not authenticated'});

// ── AUTH ───────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req,res) => {
  const { username, password, role } = req.body;
  let user;
  if (role === 'admin') {
    user = get('SELECT * FROM admins WHERE username=?',[username]);
  } else if (role === 'teacher') {
    user = get('SELECT * FROM teachers WHERE username=?',[username]);
  } else {
    user = get(`SELECT s.*, sc.name as school_name, sc.city FROM students s
      JOIN schools sc ON s.school_id=sc.id WHERE s.username=?`,[username]);
  }
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({error:'Invalid username or password'});
  req.session.userId   = user.id;
  req.session.role     = role;
  req.session.name     = user.name;
  req.session.schoolId = user.school_id || null;
  req.session.cls      = user.class || null;
  req.session.grp      = user.grp || null;
  res.json({ ok:true, role, name:user.name, id:user.id });
});

app.post('/api/auth/logout', (req,res) => { req.session.destroy(); res.json({ok:true}); });

app.get('/api/auth/me', requireAuth, (req,res) => {
  res.json({ id:req.session.userId, role:req.session.role, name:req.session.name,
             schoolId:req.session.schoolId, class:req.session.cls, grp:req.session.grp });
});

// ── SCHOOLS ────────────────────────────────────────────────────────────────────
app.get('/api/schools', requireAuth, (req,res) => res.json(all('SELECT * FROM schools ORDER BY city,name')));
app.post('/api/schools', requireAdmin, (req,res) => {
  const {name,city} = req.body;
  if (!name||!city) return res.status(400).json({error:'Name and city required'});
  run('INSERT OR IGNORE INTO schools (name,city) VALUES (?,?)',[name.trim(),city.trim()]);
  res.json(get('SELECT * FROM schools WHERE name=? AND city=?',[name.trim(),city.trim()]));
});

// ── TEACHERS ───────────────────────────────────────────────────────────────────
app.get('/api/teachers', requireAdmin, (req,res) => {
  res.json(all(`SELECT t.*, sc.name as school_name FROM teachers t
    LEFT JOIN schools sc ON t.school_id=sc.id ORDER BY t.name`));
});
app.post('/api/teachers', requireAdmin, (req,res) => {
  const {username,password,name,school_id,class:cls} = req.body;
  if (!username||!password||!name) return res.status(400).json({error:'All fields required'});
  if (get('SELECT id FROM teachers WHERE username=?',[username]))
    return res.status(400).json({error:'Username already exists'});
  const hash = bcrypt.hashSync(password,10);
  const r = run('INSERT INTO teachers (username,password,name,school_id,class) VALUES (?,?,?,?,?)',
    [username,hash,name,school_id||null,cls||null]);
  res.json(get('SELECT * FROM teachers WHERE id=?',[r.lastID]));
});
app.delete('/api/teachers/:id', requireAdmin, (req,res) => {
  run('DELETE FROM teachers WHERE id=?',[req.params.id]); res.json({ok:true});
});

// ── STUDENTS ───────────────────────────────────────────────────────────────────
app.get('/api/students', requireTeacher, (req,res) => {
  const { school_id, class: cls } = req.query;
  // Teachers only see their own school/class
  const effectiveSchoolId = req.session.role==='teacher' ? req.session.schoolId : school_id;
  const effectiveCls      = req.session.role==='teacher' ? req.session.cls      : cls;
  let sql = `SELECT s.*, sc.name as school_name, sc.city FROM students s
    JOIN schools sc ON s.school_id=sc.id WHERE 1=1`;
  const params = [];
  if (effectiveSchoolId) { sql+=' AND s.school_id=?'; params.push(effectiveSchoolId); }
  if (effectiveCls)      { sql+=' AND s.class=?';     params.push(effectiveCls); }
  sql += ' ORDER BY s.class, s.name';
  res.json(all(sql, params));
});

app.get('/api/students/:id', requireAuth, (req,res) => {
  if (req.session.role==='student' && req.session.userId!=req.params.id)
    return res.status(403).json({error:'Forbidden'});
  const s = get(`SELECT s.*, sc.name as school_name, sc.city FROM students s
    JOIN schools sc ON s.school_id=sc.id WHERE s.id=?`,[req.params.id]);
  if (!s) return res.status(404).json({error:'Not found'});
  res.json(s);
});

app.post('/api/students', requireAdmin, (req,res) => {
  const {username,password,name,class:cls,grp,school_id,academic_year} = req.body;
  if (!username||!password||!name||!cls||!grp||!school_id) return res.status(400).json({error:'All fields required'});
  if (get('SELECT id FROM students WHERE username=?',[username])) return res.status(400).json({error:'Username exists'});
  const hash = bcrypt.hashSync(password,10);
  const r = run('INSERT INTO students (username,password,name,class,grp,school_id,academic_year) VALUES (?,?,?,?,?,?,?)',
    [username,hash,name,cls,grp,school_id,academic_year||'2024-25']);
  res.json(get(`SELECT s.*, sc.name as school_name FROM students s
    JOIN schools sc ON s.school_id=sc.id WHERE s.id=?`,[r.lastID]));
});

app.delete('/api/students/:id', requireAdmin, (req,res) => {
  run('DELETE FROM students WHERE id=?',[req.params.id]); res.json({ok:true});
});

// Bulk import students from CSV
app.post('/api/students/import', requireAdmin, upload.single('csv'), (req,res) => {
  if (!req.file) return res.status(400).json({error:'No file'});
  try {
    const rows = parse(req.file.buffer.toString(),{columns:true,skip_empty_lines:true,trim:true});
    let imported=0; const errors=[];
    for (const row of rows) {
      if (get('SELECT id FROM students WHERE username=?',[row.username])) {
        errors.push(`Username exists: ${row.username}`); continue;
      }
      const school = get('SELECT * FROM schools WHERE name=? AND city=?',[row.school,row.city]);
      if (!school) { errors.push(`School not found: ${row.school}, ${row.city}`); continue; }
      run('INSERT INTO students (username,password,name,class,grp,school_id,academic_year) VALUES (?,?,?,?,?,?,?)',
        [row.username,bcrypt.hashSync(row.password||'xm1234',10),row.name,row.class,row.grp||2,school.id,row.academic_year||'2024-25']);
      imported++;
    }
    res.json({ok:true,imported,errors});
  } catch(e) { res.status(400).json({error:e.message}); }
});

// ── MODULES ────────────────────────────────────────────────────────────────────
app.get('/api/modules', requireAuth, (req,res) => {
  const { term } = req.query;
  res.json(term ? all('SELECT * FROM modules WHERE term=? ORDER BY id',[term]) : all('SELECT * FROM modules ORDER BY id'));
});
app.patch('/api/modules/:id', requireAdmin, (req,res) => {
  const { quiz_open } = req.body;
  run('UPDATE modules SET quiz_open=? WHERE id=?',[quiz_open?1:0,req.params.id]);
  res.json({ok:true});
});

// ── QUESTIONS ──────────────────────────────────────────────────────────────────
app.get('/api/modules/:id/questions', requireAuth, (req,res) => {
  const grp = req.session.grp || req.query.grp || 0;
  // Students get questions without correct answer revealed
  const qs = all('SELECT * FROM questions WHERE module_id=? AND (grp=0 OR grp=?) ORDER BY id',
    [req.params.id, grp]);
  if (req.session.role === 'student') {
    res.json(qs.map(q => ({ ...q, correct: undefined })));
  } else {
    res.json(qs);
  }
});

// Upload questions via CSV
app.post('/api/questions/import', requireAdmin, upload.single('csv'), (req,res) => {
  if (!req.file) return res.status(400).json({error:'No file'});
  try {
    const rows = parse(req.file.buffer.toString(),{columns:true,skip_empty_lines:true,trim:true});
    let imported=0; const errors=[];
    for (const row of rows) {
      if (!row.module_id||!row.question||!row.option_a||!row.option_b||!row.correct) {
        errors.push(`Missing fields in row: ${row.question?.substring(0,30)}`); continue;
      }
      run(`INSERT INTO questions (module_id,question,option_a,option_b,option_c,option_d,correct,marks,time_limit_sec,grp)
           VALUES (?,?,?,?,?,?,?,?,?,?)`,
        [row.module_id,row.question,row.option_a,row.option_b,
         row.option_c||null,row.option_d||null,
         row.correct.toUpperCase(),parseInt(row.marks)||1,
         parseInt(row.time_limit_sec)||30, parseInt(row.grp)||0]);
      imported++;
    }
    res.json({ok:true,imported,errors});
  } catch(e) { res.status(400).json({error:e.message}); }
});

app.delete('/api/questions/:id', requireAdmin, (req,res) => {
  run('DELETE FROM questions WHERE id=?',[req.params.id]); res.json({ok:true});
});

// Delete all questions for a module
app.delete('/api/modules/:id/questions', requireAdmin, (req,res) => {
  run('DELETE FROM questions WHERE module_id=?',[req.params.id]); res.json({ok:true});
});

// ── QUIZ ENGINE ────────────────────────────────────────────────────────────────
// Start or resume a quiz attempt
app.post('/api/quiz/start', requireStudent, (req,res) => {
  const { module_id, academic_year='2024-25' } = req.body;
  const studentId = req.session.userId;
  const mod = get('SELECT * FROM modules WHERE id=?',[module_id]);
  if (!mod) return res.status(404).json({error:'Module not found'});
  if (!mod.quiz_open) return res.status(403).json({error:'Quiz is not open yet'});

  const existing = get('SELECT * FROM quiz_attempts WHERE student_id=? AND module_id=? AND academic_year=?',
    [studentId,module_id,academic_year]);
  if (existing && existing.status==='completed')
    return res.status(400).json({error:'You have already completed this quiz', score:existing.score, max_score:existing.max_score});

  const grp = req.session.grp || 2;
  const questions = all('SELECT id,question,option_a,option_b,option_c,option_d,marks,time_limit_sec FROM questions WHERE module_id=? AND (grp=0 OR grp=?) ORDER BY RANDOM()',
    [module_id, grp]);
  if (!questions.length) return res.status(404).json({error:'No questions available for this module yet'});

  let attempt = existing;
  if (!attempt) {
    const r = run('INSERT INTO quiz_attempts (student_id,module_id,academic_year,status) VALUES (?,?,?,?)',
      [studentId,module_id,academic_year,'in_progress']);
    attempt = get('SELECT * FROM quiz_attempts WHERE id=?',[r.lastID]);
  }

  // Which questions already answered?
  const answered = all('SELECT question_id FROM quiz_answers WHERE attempt_id=?',[attempt.id])
    .map(a=>a.question_id);
  const remaining = questions.filter(q=>!answered.includes(q.id));

  res.json({ attempt_id:attempt.id, questions:remaining, answered_count:answered.length, total:questions.length });
});

// Submit a single answer
app.post('/api/quiz/answer', requireStudent, (req,res) => {
  const { attempt_id, question_id, answer, time_sec } = req.body;
  const attempt = get('SELECT * FROM quiz_attempts WHERE id=? AND student_id=?',
    [attempt_id, req.session.userId]);
  if (!attempt || attempt.status==='completed') return res.status(400).json({error:'Invalid attempt'});

  const q = get('SELECT * FROM questions WHERE id=?',[question_id]);
  if (!q) return res.status(404).json({error:'Question not found'});

  // Check if already answered
  const existing = get('SELECT id FROM quiz_answers WHERE attempt_id=? AND question_id=?',[attempt_id,question_id]);
  if (existing) return res.json({ok:true, already_answered:true});

  const correct = answer && answer.toUpperCase()===q.correct.toUpperCase() ? 1 : 0;
  run('INSERT INTO quiz_answers (attempt_id,question_id,answer,correct,time_sec) VALUES (?,?,?,?,?)',
    [attempt_id,question_id,answer,correct,time_sec||null]);

  res.json({ ok:true, correct: correct===1 });
});

// Finish quiz — calculate final score
app.post('/api/quiz/finish', requireStudent, (req,res) => {
  const { attempt_id, academic_year='2024-25' } = req.body;
  const studentId = req.session.userId;
  const attempt = get('SELECT * FROM quiz_attempts WHERE id=? AND student_id=?',[attempt_id,studentId]);
  if (!attempt) return res.status(404).json({error:'Attempt not found'});
  if (attempt.status==='completed') return res.json({ok:true, score:attempt.score, max_score:attempt.max_score});

  const answers  = all('SELECT qa.*, q.marks FROM quiz_answers qa JOIN questions q ON qa.question_id=q.id WHERE qa.attempt_id=?',[attempt_id]);
  const score    = answers.reduce((s,a)=>s+(a.correct?a.marks:0),0);
  const maxScore = answers.reduce((s,a)=>s+a.marks,0) || answers.length;
  const avgTime  = answers.filter(a=>a.time_sec).reduce((s,a)=>s+a.time_sec,0)/Math.max(1,answers.filter(a=>a.time_sec).length);

  // Calc group avg time for this module
  const allAttempts = all(`SELECT qa.time_sec FROM quiz_answers qa
    JOIN quiz_attempts at ON qa.attempt_id=at.id
    WHERE at.module_id=? AND qa.time_sec IS NOT NULL AND at.status='completed'`,[attempt.module_id]);
  const groupAvg = allAttempts.length ? allAttempts.reduce((s,a)=>s+a.time_sec,0)/allAttempts.length : null;

  run(`UPDATE quiz_attempts SET status='completed', score=?, max_score=?, time_sec=?, finished_at=datetime('now')
       WHERE id=?`,[score,maxScore,Math.round(avgTime)||null,attempt_id]);

  res.json({ ok:true, score, max_score:maxScore, percent:Math.round((score/maxScore)*100),
             correct:answers.filter(a=>a.correct).length, total:answers.length });
});

// ── RESULTS (derived from quiz_attempts) ──────────────────────────────────────
function getResultsForStudent(studentId, term, year) {
  return all(`SELECT qa.score, qa.max_score, qa.time_sec, qa.module_id,
    m.subject, m.name as module_name,
    (SELECT AVG(time_sec) FROM quiz_attempts WHERE module_id=m.id AND status='completed') as group_avg_sec
    FROM quiz_attempts qa JOIN modules m ON m.id=qa.module_id
    WHERE qa.student_id=? AND m.term=? AND qa.academic_year=? AND qa.status='completed'
    ORDER BY m.id`,[studentId,term,year]);
}

app.get('/api/students/:id/qq', requireAuth, (req,res) => {
  if (req.session.role==='student' && req.session.userId!=req.params.id) return res.status(403).json({error:'Forbidden'});
  const { term=1, year='2024-25' } = req.query;
  const results = getResultsForStudent(req.params.id, term, year);
  const mods = all('SELECT * FROM modules WHERE term=?',[term]);
  res.json(calcQQ(results, mods.length) || {qq:null});
});

app.get('/api/students/:id/attempts', requireAuth, (req,res) => {
  if (req.session.role==='student' && req.session.userId!=req.params.id) return res.status(403).json({error:'Forbidden'});
  const { year='2024-25' } = req.query;
  res.json(all(`SELECT qa.*, m.name as module_name, m.subject, m.term FROM quiz_attempts qa
    JOIN modules m ON m.id=qa.module_id
    WHERE qa.student_id=? AND qa.academic_year=? ORDER BY m.id`,[req.params.id,year]));
});

// ── LEADERBOARD ────────────────────────────────────────────────────────────────
app.get('/api/leaderboard', requireAuth, (req,res) => {
  const { term=1, year='2024-25', scope='national', scope_value, grp } = req.query;
  const mods = all('SELECT * FROM modules WHERE term=?',[term]);

  let students = all(`SELECT s.id, s.name, s.class, s.grp, sc.name as school, sc.city
    FROM students s JOIN schools sc ON s.school_id=sc.id
    WHERE s.academic_year=?`,[year]);

  if (scope==='school' && scope_value) students = students.filter(s=>s.school===scope_value);
  else if (scope==='city' && scope_value) students = students.filter(s=>s.city===scope_value);
  else if (scope==='class' && scope_value) students = students.filter(s=>s.class===scope_value);
  if (grp) students = students.filter(s=>s.grp==grp);

  // Teacher sees only their school
  if (req.session.role==='teacher') {
    const teacher = get('SELECT * FROM teachers WHERE id=?',[req.session.userId]);
    if (teacher?.school_id) {
      const school = get('SELECT * FROM schools WHERE id=?',[teacher.school_id]);
      if (school) students = students.filter(s=>s.school===school.name);
    }
  }

  const ranked = students.map(s=>{
    const results = getResultsForStudent(s.id, term, year);
    const qq = calcQQ(results, mods.length);
    return { ...s, qq: qq?.qq||null, band: qq?.band||null };
  }).filter(s=>s.qq!==null).sort((a,b)=>b.qq-a.qq).map((s,i)=>({...s,rank:i+1}));

  res.json(ranked);
});

// ── COMMENTS ──────────────────────────────────────────────────────────────────
app.get('/api/students/:id/comment', requireAuth, (req,res) => {
  const {term=1,year='2024-25'} = req.query;
  const c = get('SELECT * FROM teacher_comments WHERE student_id=? AND term=? AND academic_year=?',[req.params.id,term,year]);
  res.json(c||{comment:''});
});
app.post('/api/students/:id/comment', requireTeacher, (req,res) => {
  const {term=1,year='2024-25',comment} = req.body;
  const ex = get('SELECT id FROM teacher_comments WHERE student_id=? AND term=? AND academic_year=?',[req.params.id,term,year]);
  if (ex) run('UPDATE teacher_comments SET comment=? WHERE id=?',[comment,ex.id]);
  else run('INSERT INTO teacher_comments (student_id,term,academic_year,comment) VALUES (?,?,?,?)',[req.params.id,term,year,comment]);
  res.json({ok:true});
});

// ── STATS (admin dashboard) ───────────────────────────────────────────────────
app.get('/api/stats', requireAdmin, (req,res) => {
  const {year='2024-25'} = req.query;
  res.json({
    students: get('SELECT COUNT(*) as c FROM students WHERE academic_year=?',[year])?.c||0,
    teachers: get('SELECT COUNT(*) as c FROM teachers')?.c||0,
    schools:  get('SELECT COUNT(*) as c FROM schools')?.c||0,
    quizzes_completed: get('SELECT COUNT(*) as c FROM quiz_attempts WHERE status=? AND academic_year=?',['completed',year])?.c||0,
    questions: get('SELECT COUNT(*) as c FROM questions')?.c||0,
    modules_with_questions: get('SELECT COUNT(DISTINCT module_id) as c FROM questions')?.c||0,
    module_coverage: all(`SELECT m.id, m.name, m.quiz_open, COUNT(DISTINCT qa.student_id) as completions, COUNT(DISTINCT q.id) as question_count
      FROM modules m
      LEFT JOIN questions q ON q.module_id=m.id
      LEFT JOIN quiz_attempts qa ON qa.module_id=m.id AND qa.status='completed' AND qa.academic_year=?
      GROUP BY m.id ORDER BY m.id`,[year]),
  });
});

// ── PRINTABLE REPORT CARD ─────────────────────────────────────────────────────
app.get('/api/students/:id/report-card', requireAuth, (req,res) => {
  try {
    const {term=1,year='2024-25'} = req.query;
    if (req.session.role==='student' && req.session.userId!=req.params.id) return res.status(403).send('Forbidden');
    const student = get(`SELECT s.*, sc.name as school_name, sc.city FROM students s
      JOIN schools sc ON s.school_id=sc.id WHERE s.id=?`,[req.params.id]);
    if (!student) return res.status(404).send('Student not found');
    const results = getResultsForStudent(req.params.id, term, year);
    const mods    = all('SELECT * FROM modules WHERE term=?',[term]);
    const qq = calcQQ(results, mods.length);
    if (!qq) return res.send(`<html><body style="font-family:sans-serif;padding:40px;color:#666;text-align:center">
      <h2>No results yet for Term ${term}</h2><p>Complete some quizzes first!</p></body></html>`);

    const commentRow = get('SELECT * FROM teacher_comments WHERE student_id=? AND term=? AND academic_year=?',[req.params.id,term,year]);
    const comment = commentRow?.comment || (qq.qq>=70
      ? `${student.name} has had an excellent term.`
      : qq.qq>=55 ? `${student.name} has shown good progress this term.`
      : `${student.name} is developing — encourage more portal engagement.`);
    const band = getBand(qq.qq);
    const grpLabel = {1:'Group 1 · Class 4–5',2:'Group 2 · Class 6–7',3:'Group 3 · Class 8'}[student.grp]||'';
    const today = new Date().toLocaleDateString('en-IN',{day:'numeric',month:'long',year:'numeric'});
    const CIRC = 2*Math.PI*45;
    const offset = (CIRC*(1-qq.qq/100)).toFixed(1);

    const subjectBars = SUBJECTS.map(sub=>{
      const pct = qq.subjectScores[sub]||0;
      return `<div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;font-size:13px;color:#444;margin-bottom:4px">
          <span>${sub}</span><span style="font-weight:600">${pct}%</span>
        </div>
        <div style="height:7px;border-radius:4px;background:#e8e6e0">
          <div style="height:7px;border-radius:4px;background:${SUBJECT_COLORS[sub]};width:${pct}%"></div>
        </div></div>`;
    }).join('');

    res.setHeader('Content-Type','text/html');
    res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Report Card — ${student.name}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f4f0;display:flex;justify-content:center;padding:40px 20px;flex-direction:column;align-items:center}
.rc{background:#fff;border-radius:16px;overflow:hidden;width:100%;max-width:580px;box-shadow:0 4px 24px rgba(0,0,0,.10)}
.rc-header{background:#534AB7;padding:24px 28px}
.rc-body{padding:24px 28px}
.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:16px 0}
.stat{background:#fafaf8;border-radius:10px;padding:12px 14px}
.divider{border:none;border-top:1px solid #ece9e2;margin:18px 0}
@media print{body{background:#fff;padding:0}.rc{box-shadow:none;max-width:100%;border-radius:0}.rc-header{-webkit-print-color-adjust:exact;print-color-adjust:exact}.no-print{display:none}}
</style></head><body>
<div class="rc">
  <div class="rc-header">
    <div style="display:flex;justify-content:space-between;align-items:flex-start">
      <div style="font-size:13px;font-weight:600;color:#EEEDFE;letter-spacing:.05em">XM Knowledge Club</div>
      <div style="font-size:11px;font-weight:600;background:rgba(255,255,255,.2);color:#fff;padding:4px 12px;border-radius:20px">Term ${term} · ${year}</div>
    </div>
    <div style="font-size:24px;font-weight:700;color:#fff;margin-top:10px">${student.name}</div>
    <div style="font-size:12px;color:rgba(255,255,255,.65);margin-top:4px">${grpLabel} · Class ${student.class} · ${student.school_name} · ${student.city}</div>
  </div>
  <div class="rc-body">
    <div style="display:flex;align-items:center;gap:20px;margin-bottom:18px">
      <div style="position:relative;width:100px;height:100px;flex-shrink:0">
        <svg viewBox="0 0 100 100" width="100" height="100">
          <circle cx="50" cy="50" r="45" fill="none" stroke="#e8e6e0" stroke-width="7"/>
          <circle cx="50" cy="50" r="45" fill="none" stroke="${band.color}" stroke-width="7"
            stroke-dasharray="${CIRC.toFixed(1)}" stroke-dashoffset="${offset}"
            stroke-linecap="round" transform="rotate(-90 50 50)"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
          <div style="font-size:26px;font-weight:700;color:#1a1a1a">${qq.qq}</div>
          <div style="font-size:11px;color:#aaa">/100</div>
        </div>
      </div>
      <div>
        <div style="font-size:19px;font-weight:700;color:${band.color};margin-bottom:4px">${band.name}</div>
        <div style="font-size:13px;color:#666;margin-bottom:8px">Quiz Quotient · Term ${term}</div>
        <div style="font-size:11px;color:#aaa;line-height:1.6">Accuracy 50% · Knowledge Spread 15%<br>Improvement 15% · Speed 10% · Participation 10%</div>
      </div>
    </div>
    <div class="divider"></div>
    <div style="font-size:12px;font-weight:600;color:#888;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px">Subject scores</div>
    ${subjectBars}
    <div class="divider"></div>
    <div class="stat-grid">
      <div class="stat"><div style="font-size:20px;font-weight:700">${qq.modulesCompleted}/${qq.totalModules}</div><div style="font-size:11px;color:#aaa;margin-top:3px">Modules completed</div></div>
      <div class="stat"><div style="font-size:20px;font-weight:700">${qq.participation}%</div><div style="font-size:11px;color:#aaa;margin-top:3px">Participation rate</div></div>
      <div class="stat"><div style="font-size:20px;font-weight:700">${qq.speed}%</div><div style="font-size:11px;color:#aaa;margin-top:3px">Speed score</div></div>
      <div class="stat"><div style="font-size:20px;font-weight:700">${qq.spread}%</div><div style="font-size:11px;color:#aaa;margin-top:3px">Knowledge Spread</div></div>
    </div>
    <div class="divider"></div>
    <div style="background:#fafaf8;border-radius:10px;padding:14px 16px;font-size:13px;color:#555;line-height:1.7;font-style:italic">"${comment}"</div>
  </div>
  <div style="padding:14px 28px;border-top:1px solid #ece9e2;display:flex;justify-content:space-between;font-size:11px;color:#aaa">
    <span>XM Knowledge Club · Term ${term} Report · ${year}</span>
    <span>Generated ${today}</span>
  </div>
</div>
<div class="no-print" style="text-align:center;margin-top:20px">
  <button onclick="window.print()" style="padding:10px 28px;background:#534AB7;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer">Print / Save as PDF</button>
  <p style="font-size:12px;color:#aaa;margin-top:10px">Choose "Save as PDF" in the print dialog to download.</p>
</div>
</body></html>`);
  } catch(e) { res.status(500).send('Error: '+e.message); }
});

// ── CATCH-ALL ──────────────────────────────────────────────────────────────────
app.get('/', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/student*', (req,res) => res.sendFile(path.join(__dirname,'public','student','index.html')));
app.get('/teacher*', (req,res) => res.sendFile(path.join(__dirname,'public','teacher','index.html')));
app.get('/admin*',   (req,res) => res.sendFile(path.join(__dirname,'public','admin','index.html')));

// ── START ──────────────────────────────────────────────────────────────────────
initSchema().then(()=>{
  app.listen(PORT,()=>{
    console.log(`\n✅  XM Knowledge Club Platform running at http://localhost:${PORT}`);
    console.log(`    Admin:   http://localhost:${PORT}/admin   (admin / xmadmin2024)`);
    console.log(`    Teacher: http://localhost:${PORT}/teacher`);
    console.log(`    Student: http://localhost:${PORT}/student\n`);
  });
}).catch(err=>{ console.error('DB init failed:',err); process.exit(1); });
