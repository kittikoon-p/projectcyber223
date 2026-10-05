const r = require('express').Router();
const u = require('../controllers/user.controller');
const { auth } = require('../middleware/auth');

r.use(auth);
r.get('/profile', u.me);
r.put('/profile', u.updateMe);
r.put('/password', u.changePassword);
module.exports = r;
