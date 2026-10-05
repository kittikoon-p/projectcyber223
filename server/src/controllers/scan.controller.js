const db = require('../config/db');
const { scanUrl } = require('../services/scanner.service');
const logSecurity = require('../utils/logger');

exports.run = async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'url required' });
  try { new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL format' }); }
  try {
    const result = await scanUrl(url);
    const [r] = await db.query(
      'INSERT INTO scans (user_id, url, status_code, score, headers_json, findings_json) VALUES (?,?,?,?,?,?)',
      [req.user.id, url, result.statusCode, result.score, JSON.stringify(result.headers), JSON.stringify(result.findings)]
    );
    await logSecurity(req, req.user.id, 'SECURITY_SCAN', { url, score: result.score });
    res.status(201).json({ id: r.insertId, url, ...result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
};

exports.list = async (req, res) => {
  const [rows] = await db.query('SELECT id, url, status_code, score, created_at FROM scans WHERE user_id=? ORDER BY created_at DESC', [req.user.id]);
  res.json(rows);
};

exports.getOne = async (req, res) => {
  const [rows] = await db.query('SELECT * FROM scans WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
};

exports.remove = async (req, res) => {
  const [r] = await db.query('DELETE FROM scans WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Not found' });
  await logSecurity(req, req.user.id, 'SCAN_DELETED', { scanId: req.params.id });
  res.json({ message: 'Scan deleted' });
};
