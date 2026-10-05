const r = require('express').Router();
const a = require('../controllers/auth.controller');
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts' } });

r.post('/register', a.register);
r.post('/login', loginLimiter, a.login);
r.post('/logout', a.logout);
r.post('/refresh', a.refresh);
r.post('/forgot-password', a.forgotPassword);
r.post('/reset-password', a.resetPassword);
module.exports = r;
