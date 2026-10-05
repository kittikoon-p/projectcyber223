const db = require('../config/db');
const logSecurity = require('../utils/logger');

exports.dashboard = async (req, res) => {
  const [[u]] = await db.query("SELECT COUNT(*) total, SUM(role='admin') admins FROM users");
  const [[s]] = await db.query('SELECT COUNT(*) total, ROUND(AVG(score)) avgScore FROM scans');
  const [recent] = await db.query('SELECT DATE(created_at) day, COUNT(*) count FROM scans WHERE created_at > NOW() - INTERVAL 7 DAY GROUP BY DATE(created_at)');
  res.json({ users: u.total, admins: u.admins, scans: s.total, avgScore: s.avgScore, scansLast7Days: recent });
};

exports.users = async (req, res) => {
  const [rows] = await db.query('SELECT id, name, email, role, created_at FROM users ORDER BY id');
  res.json(rows);
};

exports.deleteUser = async (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  const [r] = await db.query("DELETE FROM users WHERE id=? AND role='user'", [id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'User not found' });
  await logSecurity(req, req.user.id, 'USER_DELETED', { deletedUserId: id });
  res.json({ message: 'User deleted' });
};

exports.scans = async (req, res) => {
  const [rows] = await db.query('SELECT s.id, s.url, s.score, s.status_code, s.created_at, u.email FROM scans s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC LIMIT 100');
  res.json(rows);
};

exports.history = async (req, res) => {
  const [rows] = await db.query('SELECT l.*, u.email FROM security_logs l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC LIMIT 200');
  res.json(rows);
};

exports.logs = exports.history;
