const r = require('express').Router();
const a = require('../controllers/admin.controller');
const { auth, requireAdmin } = require('../middleware/auth');

r.use(auth, requireAdmin);
r.get('/dashboard', a.dashboard);
r.get('/users', a.users);
r.delete('/users/:id', a.deleteUser);
r.get('/scans', a.scans);
r.get('/history', a.history);
r.get('/logs', a.logs);
module.exports = r;
