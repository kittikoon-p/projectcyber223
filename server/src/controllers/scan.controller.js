const db = require('../config/db');
const { scanUrl } = require('../services/scanner.service');
const logSecurity = require('../utils/logger');

exports.run = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    const result = await scanUrl(url);
    const [r] = await db.query(
      'INSERT INTO scans (user_id, url, status_code, score, headers_json, findings_json) VALUES (?,?,?,?,?,?)',
      [req.user.id, url, result.statusCode, result.score, JSON.stringify(result.headers), JSON.stringify(result.findings)]
    );
    await logSecurity(req, req.user.id, 'SCAN_RUN', { url, score: result.score });
    res.status(201).json({ id: r.insertId, url, ...result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
};

exports.getOne = async (req, res) => {
  const [rows] = await db.query('SELECT * FROM scans WHERE id=?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  if (req.user.role !== 'admin' && rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  res.json(rows[0]);
};
