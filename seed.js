require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com') ? { rejectUnauthorized: false } : false,
});

async function run() {
  const hash = await bcrypt.hash('admin123', 10);
  const r = await pool.query(
    `INSERT INTO users (login_code, password_hash, role, full_name)
     VALUES ('999999', $1, 'ADMIN', 'Super Admin')
     ON CONFLICT (login_code) DO UPDATE SET password_hash=EXCLUDED.password_hash
     RETURNING id`,
    [hash]
  );
  console.log('✅ Admin user ready. Login: 999999 / admin123');
  process.exit(0);
}

run().catch(e => { console.error(e); process.exit(1); });
