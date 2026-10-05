const r = require('express').Router();
const u = require('../controllers/user.controller');
const { auth } = require('../middleware/auth');

r.use(auth);
r.get('/me', u.me);
r.put('/me', u.updateMe);
r.put('/me/password', u.changePassword);
r.get('/me/scans', u.myScans);
module.exports = r;
