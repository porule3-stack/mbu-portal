require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com') ? { rejectUnauthorized: false } : false,
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Create tables on startup (idempotent)
async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS regions (
      id SERIAL PRIMARY KEY,
      region_name VARCHAR(80) UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS divisions (
      id SERIAL PRIMARY KEY,
      region_id INT REFERENCES regions(id),
      division_name VARCHAR(120) NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sub_divisions (
      id SERIAL PRIMARY KEY,
      division_id INT REFERENCES divisions(id),
      sub_division VARCHAR(150) NOT NULL,
      head_name VARCHAR(120),
      head_mobile VARCHAR(20),
      login_code VARCHAR(10) UNIQUE
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      login_code VARCHAR(10) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL,
      division_id INT REFERENCES divisions(id),
      sub_div_id INT REFERENCES sub_divisions(id),
      full_name VARCHAR(120),
      mobile VARCHAR(20),
      is_active BOOLEAN DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS camp_reports (
      id BIGSERIAL PRIMARY KEY,
      report_date DATE NOT NULL,
      region_id INT,
      division_id INT,
      sub_division_id INT,
      station_id VARCHAR(40),
      machine_id VARCHAR(80),
      udise_code VARCHAR(20),
      school_address TEXT,
      district VARCHAR(80),
      operator_name VARCHAR(120),
      operator_contact VARCHAR(20),
      new_aadhaar INT DEFAULT 0,
      mbu_updation INT DEFAULT 0,
      other_updation INT DEFAULT 0,
      total_transactions INT DEFAULT 0,
      entered_by INT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('✅ Tables ready');
}

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date() }));

// Seed a single admin user if no users exist (for testing)
app.post('/api/dev/seed-admin', async (req, res) => {
  try {
    const existing = await pool.query('SELECT COUNT(*) FROM users');
    if (existing.rows[0].count > 0) {
      return res.json({ message: 'Users already exist. Skipping.' });
    }
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      `INSERT INTO users (login_code, password_hash, role, full_name)
       VALUES ('999999', $1, 'ADMIN', 'Super Admin')`,
      [hash]
    );
    res.json({ message: 'Admin user created. Login: 999999 / admin123' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Login
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
      { id: user.id, code: user.login_code, role: user.role, name: user.full_name },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, user: { name: user.full_name, role: user.role, code: user.login_code } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

ensureTables()
  .then(() => {
    app.listen(PORT, () => console.log(`✅ MBU Portal on port ${PORT}`));
  })
  .catch(err => {
    console.error('❌ Failed to start:', err);
    process.exit(1);
  });
