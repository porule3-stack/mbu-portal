require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com') ? { rejectUnauthorized: false } : false,
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============= DB SCHEMA =============
async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS regions (
      id SERIAL PRIMARY KEY,
      region_name VARCHAR(80) UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS divisions (
      id SERIAL PRIMARY KEY,
      region_id INT REFERENCES regions(id),
      division_name VARCHAR(150) NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sub_divisions (
      id SERIAL PRIMARY KEY,
      division_id INT REFERENCES divisions(id),
      sub_division VARCHAR(200) NOT NULL,
      head_name VARCHAR(150),
      head_mobile VARCHAR(20),
      login_code VARCHAR(10) UNIQUE
    );
    CREATE TABLE IF NOT EXISTS schools (
      id BIGSERIAL PRIMARY KEY,
      udise_code VARCHAR(20) UNIQUE NOT NULL,
      school_name VARCHAR(300),
      district VARCHAR(100),
      block VARCHAR(100)
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      login_code VARCHAR(10) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL,
      division_id INT REFERENCES divisions(id),
      sub_div_id INT REFERENCES sub_divisions(id),
      full_name VARCHAR(150),
      mobile VARCHAR(20),
      is_active BOOLEAN DEFAULT TRUE,
      must_change_password BOOLEAN DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS camp_reports (
      id BIGSERIAL PRIMARY KEY,
      report_date DATE NOT NULL,
      region_id INT,
      division_id INT,
      sub_division_id INT,
      station_id VARCHAR(50),
      machine_id VARCHAR(100),
      udise_code VARCHAR(20),
      school_address TEXT,
      district VARCHAR(100),
      operator_name VARCHAR(150),
      operator_contact VARCHAR(20),
      new_aadhaar INT DEFAULT 0,
      mbu_updation INT DEFAULT 0,
      other_updation INT DEFAULT 0,
      total_transactions INT DEFAULT 0,
      entered_by INT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_schools_udise ON schools(udise_code);
  `);
  console.log('✅ Tables ready');
}

// ============= AUTH MIDDLEWARE =============
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============= PUBLIC ROUTES =============
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date() }));

app.post('/api/auth/login', async (req, res) => {
  const { login_code, password } = req.body;
  if (!login_code || !password) return res.status(400).json({ error: 'Missing credentials' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE login_code=$1 AND is_active=true', [login_code]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'Invalid code' });
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid password' });
    const token = jwt.sign(
      {
        id: user.id,
        code: user.login_code,
        role: user.role,
        name: user.full_name,
        division_id: user.division_id,
        sub_div_id: user.sub_div_id,
        must_change_password: user.must_change_password,
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({
      token,
      user: {
        name: user.full_name,
        role: user.role,
        code: user.login_code,
        must_change_password: user.must_change_password,
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < 6) return res.status(400).json({ error: 'Password too short (min 6 chars)' });
  try {
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password_hash=$1, must_change_password=false WHERE id=$2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', requireAuth, (req, res) => res.json(req.user));

// ============= SEED ENDPOINTS (one-time setup) =============
app.post('/api/dev/seed-admin', async (req, res) => {
app.post('/api/dev/reset-db', async (req, res) => {
  try {
    await pool.query(`
      DROP TABLE IF EXISTS camp_reports CASCADE;
      DROP TABLE IF EXISTS users CASCADE;
      DROP TABLE IF EXISTS sub_divisions CASCADE;
      DROP TABLE IF EXISTS divisions CASCADE;
      DROP TABLE IF EXISTS regions CASCADE;
      DROP TABLE IF EXISTS schools CASCADE;
    `);
    res.json({ ok: true, message: 'All tables dropped. Wait for restart, then run seed-divisions.' });
    // Restart the app so ensureTables() runs and recreates them
    setTimeout(() => process.exit(0), 1500);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

  
  try {
    const existing = await pool.query('SELECT COUNT(*) FROM users');
    if (existing.rows[0].count > 0) {
      return res.json({ message: 'Users already exist. Skipping.' });
    }
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      `INSERT INTO users (login_code, password_hash, role, full_name, must_change_password)
       VALUES ('999999', $1, 'ADMIN', 'Super Admin', false)`,
      [hash]
    );
    res.json({ message: 'Admin user created. Login: 999999 / admin123' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/dev/seed-divisions', async (req, res) => {
  try {
    const dataPath = path.join(__dirname, 'seed', 'divisions.json');
    if (!fs.existsSync(dataPath)) {
      return res.status(400).json({ error: 'seed/divisions.json not found in repo' });
    }
    const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));

    // Clear existing division/user data (keep admin)
    await pool.query(`DELETE FROM users WHERE role != 'ADMIN'`);
    await pool.query(`DELETE FROM sub_divisions`);
    await pool.query(`DELETE FROM divisions`);
    await pool.query(`DELETE FROM regions`);

    const defaultPassword = 'Mbu@2026';
    const hash = await bcrypt.hash(defaultPassword, 10);

    // 1. Regions
    const regionMap = {};
    for (const row of data) {
      if (!regionMap[row.region]) {
        const r = await pool.query(
          `INSERT INTO regions (region_name) VALUES ($1) ON CONFLICT (region_name) DO UPDATE SET region_name=EXCLUDED.region_name RETURNING id`,
          [row.region]
        );
        regionMap[row.region] = r.rows[0].id;
      }
    }

    // 2. Divisions
    const divisionMap = {};
    for (const row of data) {
      if (!divisionMap[row.division]) {
        const r = await pool.query(
          `INSERT INTO divisions (region_id, division_name) VALUES ($1,$2) RETURNING id`,
          [regionMap[row.region], row.division]
        );
        divisionMap[row.division] = r.rows[0].id;
      }
    }

    // 3. Sub-divisions + users with login codes
    const regionCodeMap = { 'Ahmedabad Region': '1', 'Rajkot Region': '2', 'Vadodara Region': '3' };
    const regionDivCounter = {};
    const divSubCounter = {};

    const createdCodes = [];
    for (const row of data) {
      const regionCode = regionCodeMap[row.region] || '9';
      regionDivCounter[row.region] = (regionDivCounter[row.region] || 0) + 1;
      const divisionCode = String(regionDivCounter[row.region]).padStart(2, '0');

      divSubCounter[row.division] = (divSubCounter[row.division] || 0) + 1;
      const subCode = String(divSubCounter[row.division]).padStart(2, '0');

      const loginCode = `${regionCode}${divisionCode}${subCode}`;

      const subRes = await pool.query(
        `INSERT INTO sub_divisions (division_id, sub_division, head_name, head_mobile, login_code)
         VALUES ($1,$2,$3,$4,$5) RETURNING id`,
        [divisionMap[row.division], row.sub_division, row.head_name, row.head_mobile, loginCode]
      );

      await pool.query(
        `INSERT INTO users (login_code, password_hash, role, division_id, sub_div_id, full_name, mobile, must_change_password)
         VALUES ($1,$2,'SUBDIV',$3,$4,$5,$6,true)`,
        [loginCode, hash, divisionMap[row.division], subRes.rows[0].id, row.head_name, row.head_mobile]
      );

      createdCodes.push({ code: loginCode, name: row.head_name, division: row.division, sub: row.sub_division, mobile: row.head_mobile });
    }

    res.json({
      message: `Seeded ${createdCodes.length} sub-divisions and users. Default password: ${defaultPassword}`,
      preview: createdCodes.slice(0, 10),
      total: createdCodes.length,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ============= CAMP REPORTS =============
app.post('/api/camp-reports', requireAuth, async (req, res) => {
  const b = req.body;
  if (req.user.role === 'SUBDIV' && !req.user.sub_div_id) {
    return res.status(403).json({ error: 'No sub-division assigned' });
  }
  try {
    // Strict UDISE check
    const sch = await pool.query('SELECT id FROM schools WHERE udise_code=$1', [b.udise_code]);
    if (sch.rows.length === 0) {
      return res.status(400).json({ error: 'UDISE code not found in master list' });
    }
    const total = (+b.new_aadhaar || 0) + (+b.mbu_updation || 0) + (+b.other_updation || 0);

    // Resolve region_id from division
    const divRes = await pool.query('SELECT region_id FROM divisions WHERE id=$1', [req.user.division_id]);
    const regionId = divRes.rows[0]?.region_id;

    const r = await pool.query(
      `INSERT INTO camp_reports
       (report_date, region_id, division_id, sub_division_id, station_id, machine_id, udise_code,
        school_address, district, operator_name, operator_contact, new_aadhaar, mbu_updation,
        other_updation, total_transactions, entered_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
      [
        b.report_date,
        regionId,
        req.user.division_id,
        req.user.sub_div_id,
        b.station_id,
        b.machine_id,
        b.udise_code,
        b.school_address,
        b.district,
        b.operator_name,
        b.operator_contact,
        +b.new_aadhaar || 0,
        +b.mbu_updation || 0,
        +b.other_updation || 0,
        total,
        req.user.id,
      ]
    );
    res.json({ ok: true, id: r.rows[0].id, total });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/camp-reports', requireAuth, async (req, res) => {
  const { date_from, date_to, division_id, limit = 200 } = req.query;
  const conds = [];
  const vals = [];
  let i = 1;
  if (date_from) { conds.push(`c.report_date >= $${i++}`); vals.push(date_from); }
  if (date_to) { conds.push(`c.report_date <= $${i++}`); vals.push(date_to); }
  if (req.user.role === 'SUBDIV') { conds.push(`c.division_id = $${i++}`); vals.push(req.user.division_id); }
  if (req.user.role === 'DIVISION') { conds.push(`c.division_id = $${i++}`); vals.push(req.user.division_id); }
  if (division_id && req.user.role === 'ADMIN') { conds.push(`c.division_id = $${i++}`); vals.push(division_id); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  try {
    const r = await pool.query(
      `SELECT c.*, r.region_name, d.division_name, s.sub_division
       FROM camp_reports c
       LEFT JOIN regions r ON r.id = c.region_id
       LEFT JOIN divisions d ON d.id = c.division_id
       LEFT JOIN sub_divisions s ON s.id = c.sub_division_id
       ${where}
       ORDER BY c.report_date DESC, c.id DESC LIMIT ${parseInt(limit)}`,
      vals
    );
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ============= DASHBOARD =============
app.get('/api/dashboard/summary', requireAuth, async (req, res) => {
  const { from, to } = req.query;
  const conds = [];
  const vals = [];
  let i = 1;
  if (from) { conds.push(`report_date >= $${i++}`); vals.push(from); }
  if (to) { conds.push(`report_date <= $${i++}`); vals.push(to); }

  let scopeCond = '';
  if (req.user.role === 'SUBDIV') { scopeCond = `division_id = $${i++}`; vals.push(req.user.division_id); }
  else if (req.user.role === 'DIVISION') { scopeCond = `division_id = $${i++}`; vals.push(req.user.division_id); }

  if (scopeCond) conds.push(scopeCond);
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';

  try {
    const overall = await pool.query(
      `SELECT
        COUNT(*) AS camps,
        COUNT(DISTINCT udise_code) AS schools,
        COALESCE(SUM(new_aadhaar),0) AS new_aadhaar,
        COALESCE(SUM(mbu_updation),0) AS mbu,
        COALESCE(SUM(other_updation),0) AS other,
        COALESCE(SUM(total_transactions),0) AS total
       FROM camp_reports ${where}`,
      vals
    );
    const byDivision = await pool.query(
      `SELECT d.division_name, r.region_name,
        COUNT(c.id) AS camps,
        COUNT(DISTINCT c.udise_code) AS schools,
        COALESCE(SUM(c.new_aadhaar),0) AS new_aadhaar,
        COALESCE(SUM(c.mbu_updation),0) AS mbu,
        COALESCE(SUM(c.other_updation),0) AS other,
        COALESCE(SUM(c.total_transactions),0) AS total
       FROM camp_reports c
       JOIN divisions d ON d.id = c.division_id
       JOIN regions r ON r.id = c.region_id
       ${where}
       GROUP BY d.division_name, r.region_name
       ORDER BY total DESC`,
      vals
    );
    const daily = await pool.query(
      `SELECT report_date, SUM(total_transactions) AS total
       FROM camp_reports ${where}
       GROUP BY report_date ORDER BY report_date DESC LIMIT 30`,
      vals
    );
    res.json({
      overall: overall.rows[0],
      byDivision: byDivision.rows,
      daily: daily.rows.reverse(),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ============= MASTER DATA =============
app.get('/api/master/sub-divisions', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM sub_divisions ORDER BY division_id, sub_division');
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/master/schools', requireAuth, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT udise_code, school_name, district FROM schools
       WHERE udise_code ILIKE $1 OR school_name ILIKE $1 LIMIT 20`,
      [`%${q}%`]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Bulk upload schools (JSON array)
app.post('/api/dev/seed-schools', async (req, res) => {
  const arr = req.body.schools;
  if (!Array.isArray(arr)) return res.status(400).json({ error: 'Expected {schools: [...]}' });
  try {
    let inserted = 0;
    for (const s of arr) {
      await pool.query(
        `INSERT INTO schools (udise_code, school_name, district, block)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (udise_code) DO UPDATE SET school_name=EXCLUDED.school_name`,
        [String(s.udise_code), s.school_name || '', s.district || '', s.block || '']
      );
      inserted++;
    }
    res.json({ ok: true, inserted });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Password list download (admin only)
app.get('/api/admin/credentials', requireAuth, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  try {
    const r = await pool.query(`
      SELECT u.login_code, u.full_name, u.mobile, d.division_name, r.region_name, s.sub_division
      FROM users u
      LEFT JOIN divisions d ON d.id = u.division_id
      LEFT JOIN regions r ON r.id = d.region_id
      LEFT JOIN sub_divisions s ON s.id = u.sub_div_id
      WHERE u.role = 'SUBDIV'
      ORDER BY u.login_code
    `);
    res.json({ default_password: 'Mbu@2026', users: r.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// SPA fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============= START =============
ensureTables()
  .then(() => {
    app.listen(PORT, () => console.log(`✅ MBU Portal on port ${PORT}`));
  })
  .catch(err => {
    console.error('❌ Failed to start:', err);
    process.exit(1);
  });
