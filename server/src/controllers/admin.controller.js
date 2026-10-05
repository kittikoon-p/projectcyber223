const db = require('../config/db');
const logSecurity = require('../utils/logger');

exports.dashboard = async (req, res) => {
  const [[u]] = await db.query("SELECT COUNT(*) total, SUM(role='admin') admins FROM users");
  const [[s]] = await db.query('SELECT COUNT(*) total, ROUND(AVG(score)) avgScore FROM scans');
  const [[today]] = await db.query('SELECT COUNT(*) c FROM scans WHERE DATE(created_at)=CURDATE()');
  const [recent] = await db.query('SELECT DATE(created_at) day, COUNT(*) count FROM scans WHERE created_at > NOW() - INTERVAL 7 DAY GROUP BY DATE(created_at)');
  res.json({ users: u.total, admins: u.admins, scans: s.total, avgScore: s.avgScore, scansToday: today.c, scansLast7Days: recent });
};

exports.statistics = async (req, res) => {
  const [[u]] = await db.query("SELECT COUNT(*) totalUsers, SUM(role='admin') admins, SUM(role='user') users FROM users");
  const [[s]] = await db.query('SELECT COUNT(*) totalScans, ROUND(AVG(score)) avgScore, SUM(score < 50) lowScore, SUM(created_at > NOW() - INTERVAL 1 DAY) last24h FROM scans');
  const [[l]] = await db.query('SELECT COUNT(*) totalLogs FROM security_logs');
  res.json({ ...u, ...s, ...l });
};

exports.users = async (req, res) => {
  const [rows] = await db.query('SELECT id, username, email, role, created_at FROM users ORDER BY id');
  res.json(rows);
};

exports.userById = async (req, res) => {
  const [rows] = await db.query('SELECT id, username, email, role, created_at FROM users WHERE id=?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'User not found' });
  res.json(rows[0]);
};

exports.deleteUser = async (req, res) => {
  const p = req.params.id;
  if (p === 'admin') return res.status(403).json({ error: 'Cannot delete admin' });
  const id = parseInt(p);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
  const [[target]] = await db.query('SELECT role FROM users WHERE id=?', [id]);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'admin') return res.status(403).json({ error: 'Cannot delete admin' });
  await db.query('DELETE FROM users WHERE id=?', [id]);
  await logSecurity(req, req.user.id, 'USER_DELETED', { deletedUserId: id });
  res.json({ message: 'User deleted' });
};

exports.scans = async (req, res) => {
  const [rows] = await db.query('SELECT s.id, s.url, s.score, s.status_code, s.created_at, u.username, u.email FROM scans s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC LIMIT 100');
  res.json(rows);
};

exports.scanById = async (req, res) => {
  const [rows] = await db.query('SELECT s.*, u.username, u.email FROM scans s JOIN users u ON u.id=s.user_id WHERE s.id=?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Scan not found' });
  res.json(rows[0]);
};

exports.deleteScan = async (req, res) => {
  const [r] = await db.query('DELETE FROM scans WHERE id=?', [req.params.id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Scan not found' });
  await logSecurity(req, req.user.id, 'SCAN_DELETED', { scanId: req.params.id });
  res.json({ message: 'Scan deleted' });
};

exports.history = async (req, res) => {
  const [rows] = await db.query('SELECT s.id, s.url, s.score, s.status_code, s.created_at, u.username, u.email FROM scans s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC LIMIT 200');
  res.json(rows);
};

exports.userHistory = async (req, res) => {
  const [rows] = await db.query('SELECT id, url, score, status_code, created_at FROM scans WHERE user_id=? ORDER BY created_at DESC', [req.params.id]);
  res.json(rows);
};

exports.logs = async (req, res) => {
  const { action } = req.query;
  let sql = 'SELECT l.*, u.username, u.email FROM security_logs l LEFT JOIN users u ON u.id=l.user_id';
  const params = [];
  if (action) { sql += ' WHERE l.action = ?'; params.push(action); }
  sql += ' ORDER BY l.created_at DESC LIMIT 200';
  const [rows] = await db.query(sql, params);
  res.json(rows);
};

exports.system = async (req, res) => {
  res.json({ nodeVersion: process.version, uptime: process.uptime(), platform: process.platform, db: 'mysql', status: 'ok' });
};

exports.getSettings = async (req, res) => {
  const [rows] = await db.query('SELECT `key`, `value` FROM system_settings');
  const obj = {};
  rows.forEach(r => { obj[r.key] = isNaN(+r.value) ? r.value : +r.value; });
  res.json(obj);
};

exports.updateSettings = async (req, res) => {
  for (const [k, v] of Object.entries(req.body || {})) {
    await db.query('INSERT INTO system_settings (`key`,`value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value`=?', [k, String(v), String(v)]);
  }
  await logSecurity(req, req.user.id, 'SETTINGS_UPDATED', req.body);
  res.json({ message: 'Settings updated' });
};
