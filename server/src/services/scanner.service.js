const PRIVATE_HOSTS = ['localhost', '127.', '0.0.0.0', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '169.254.', '::1'];

async function scanUrl(target) {
  let url;
  try { url = new URL(target); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only http/https allowed');
  const host = url.hostname.toLowerCase();
  if (PRIVATE_HOSTS.some(p => host.startsWith(p) || host === 'localhost')) throw new Error('Private/local addresses not allowed');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  let res;
  try {
    res = await fetch(url, { method: 'GET', redirect: 'follow', signal: controller.signal, headers: { 'User-Agent': 'SecureCheck/1.0' } });
  } finally { clearTimeout(timer); }

  const h = res.headers;
  const checks = [];
  const add = (name, status, message) => checks.push({ header: name, status, message });

  const hsts = h.get('strict-transport-security');
  if (!hsts) add('Strict-Transport-Security', 'fail', 'Missing HSTS header');
  else if (/max-age=(\d+)/.exec(hsts) && parseInt(RegExp.$1) >= 15552000) add('Strict-Transport-Security', 'pass', hsts);
  else add('Strict-Transport-Security', 'warn', 'max-age too small');

  const csp = h.get('content-security-policy');
  add('Content-Security-Policy', csp ? 'pass' : 'fail', csp ? 'Present' : 'Missing CSP');

  const xfo = h.get('x-frame-options');
  add('X-Frame-Options', xfo && /DENY|SAMEORIGIN/i.test(xfo) ? 'pass' : 'fail', xfo || 'Missing');

  const xcto = h.get('x-content-type-options');
  add('X-Content-Type-Options', xcto === 'nosniff' ? 'pass' : 'fail', xcto || 'Missing');

  const rp = h.get('referrer-policy');
  add('Referrer-Policy', rp ? 'pass' : 'warn', rp || 'Missing');

  const pp = h.get('permissions-policy');
  add('Permissions-Policy', pp ? 'pass' : 'warn', pp || 'Missing');

  const server = h.get('server');
  add('Server', server && /\d/.test(server) ? 'warn' : 'pass', server || 'Not disclosed');

  const powered = h.get('x-powered-by');
  add('X-Powered-By', powered ? 'warn' : 'pass', powered || 'Not disclosed');

  const score = Math.round(checks.reduce((s, c) => s + (c.status === 'pass' ? 100 : c.status === 'warn' ? 50 : 0), 0) / checks.length);

  const headersObj = {};
  h.forEach((v, k) => { headersObj[k] = v; });
  return { statusCode: res.status, score, headers: headersObj, findings: checks };
}

module.exports = { scanUrl };
