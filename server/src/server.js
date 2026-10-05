const bcrypt = require('bcrypt');
const app = require('./app');
const db = require('./config/db');

async function seedAdmin() {
  const [rows] = await db.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
  if (rows.length) return;
  const email = process.env.ADMIN_EMAIL || 'admin@securecheck.local';
  const password = process.env.ADMIN_PASSWORD || 'Admin@1234';
  const hash = await bcrypt.hash(password, 10);
  await db.query("INSERT INTO users (username, email, password_hash, role) VALUES ('Administrator', ?, ?, 'admin')", [email, hash]);
  console.log(`Admin seeded: ${email}`);
}

async function waitForDb(retries = 30) {
  for (let i = 0; i < retries; i++) {
    try { await db.query('SELECT 1'); return; }
    catch { await new Promise(r => setTimeout(r, 2000)); }
  }
  throw new Error('DB not reachable');
}

(async () => {
  await waitForDb();
  await seedAdmin();
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`SecureCheck API on :${port}`));
})().catch(e => { console.error(e); process.exit(1); });
