const db = require('/app/src/config/db');
const bcrypt = require('bcrypt');
(async () => {
  const [rows] = await db.query("SELECT id,email,password_hash,reset_token FROM users WHERE email='resetme@gmail.com'");
  console.log(rows[0]);
  console.log('compare NewPassword123!:', await bcrypt.compare('NewPassword123!', rows[0].password_hash));
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
