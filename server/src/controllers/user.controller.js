const bcrypt = require('bcrypt');
const db = require('../config/db');
const logSecurity = require('../utils/logger');

exports.me = async (req, res) => {
  const [rows] = await db.query('SELECT id, username, email, role, created_at FROM users WHERE id=?', [req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
};

exports.updateMe = async (req, res) => {
  const { username, email } = req.body;
  if (username !== undefined && !username.trim()) return res.status(400).json({ error: 'username cannot be empty' });
  if (email !== undefined && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'valid email required' });
  if (username === undefined && email === undefined) return res.status(400).json({ error: 'username or email required' });
  try {
    if (username !== undefined) await db.query('UPDATE users SET username=? WHERE id=?', [username.trim(), req.user.id]);
    if (email !== undefined) await db.query('UPDATE users SET email=? WHERE id=?', [email, req.user.id]);
    await logSecurity(req, req.user.id, 'PROFILE_UPDATE', { username, email });
    res.json({ message: 'Profile updated' });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email in use' });
    throw e;
  }
};

exports.changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword || newPassword.length < 8) return res.status(400).json({ error: 'oldPassword and newPassword(min 8) required' });
  const [rows] = await db.query('SELECT password_hash FROM users WHERE id=?', [req.user.id]);
  if (!(await bcrypt.compare(oldPassword, rows[0].password_hash))) return res.status(401).json({ error: 'Wrong current password' });
  await db.query('UPDATE users SET password_hash=? WHERE id=?', [await bcrypt.hash(newPassword, 10), req.user.id]);
  await logSecurity(req, req.user.id, 'PASSWORD_CHANGE', {});
  res.json({ message: 'Password changed' });
};
