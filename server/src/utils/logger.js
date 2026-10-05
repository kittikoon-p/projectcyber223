const db = require('../config/db');

async function logSecurity(req, userId, action, details) {
  try {
    await db.query(
      'INSERT INTO security_logs (user_id, action, ip_address, user_agent, details_json) VALUES (?,?,?,?,?)',
      [userId || null, action, req.ip, (req.headers['user-agent'] || '').slice(0, 255), details ? JSON.stringify(details) : null]
    );
  } catch (e) { console.error('log failed', e.message); }
}
module.exports = logSecurity;
