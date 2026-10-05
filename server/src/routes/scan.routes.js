const r = require('express').Router();
const s = require('../controllers/scan.controller');
const { auth } = require('../middleware/auth');
const rateLimit = require('express-rate-limit');

r.use(auth);
r.post('/', rateLimit({ windowMs: 60 * 1000, max: 10 }), s.run);
r.get('/:id', s.getOne);
module.exports = r;
