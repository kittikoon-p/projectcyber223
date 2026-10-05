const app = document.getElementById('app');
let accessToken = localStorage.getItem('accessToken') || null;
let currentUser = JSON.parse(localStorage.getItem('user') || 'null');

const api = async (path, opts = {}) => {
  opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (accessToken) opts.headers.Authorization = 'Bearer ' + accessToken;
  opts.credentials = 'include';
  const res = await fetch('/api' + path, opts);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && accessToken) {
    const r = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' });
    if (r.ok) { accessToken = (await r.json()).accessToken; localStorage.setItem('accessToken', accessToken); return api(path, opts); }
    logout();
  }
  if (!res.ok) throw new Error(data.error || 'Error');
  return data;
};

function setSession(token, user) {
  accessToken = token; currentUser = user;
  localStorage.setItem('accessToken', token);
  localStorage.setItem('user', JSON.stringify(user));
  render();
}
function logout() {
  api('/auth/logout', { method: 'POST' }).catch(() => {});
  accessToken = null; currentUser = null;
  localStorage.clear(); render();
}
function nav() {
  const n = document.getElementById('nav');
  if (!currentUser) n.innerHTML = '<a href="#login">Login</a><a href="#register">Register</a><a href="#forgot">Forgot</a>';
  else n.innerHTML = `<a href="#dashboard">Dashboard</a><a href="#scan">Scan</a><a href="#profile">Profile</a>` +
    (currentUser.role === 'admin' ? '<a href="#admin">Admin</a>' : '') + '<a href="#" id="lo">Logout</a>';
  const lo = document.getElementById('lo'); if (lo) lo.onclick = e => { e.preventDefault(); logout(); };
}

function render() {
  nav();
  const hash = location.hash || (currentUser ? '#dashboard' : '#login');
  const routes = { '#login': loginPage, '#register': registerPage, '#forgot': forgotPage, '#reset': resetPage, '#dashboard': dashboardPage, '#scan': scanPage, '#profile': profilePage, '#admin': adminPage };
  (routes[hash] || loginPage)();
}
window.onhashchange = render;

function form(fields, button, onsubmit) {
  const f = document.createElement('form');
  fields.forEach(([t, k, type]) => { const i = document.createElement('input'); i.placeholder = t; i.name = k; i.type = type || 'text'; f.appendChild(i); });
  const b = document.createElement('button'); b.textContent = button; f.appendChild(b);
  const msg = document.createElement('p'); f.appendChild(msg);
  f.onsubmit = async e => { e.preventDefault(); msg.textContent = ''; const body = {}; new FormData(f).forEach((v, k) => body[k] = v);
    try { await onsubmit(body); } catch (err) { msg.textContent = err.message; msg.style.color = '#f87171'; } };
  return f;
}

const hero = `<div class="hero"><h2>&#128737; SecureCheck API</h2><p>เครื่องมือตรวจสอบความปลอดภัยของ REST API ตรวจ Security Headers พร้อมระบบ JWT Authentication และ Role-Based Access Control</p><div class="features"><div class="feature">&#128274; JWT Auth</div><div class="feature">&#128100; User / Admin</div><div class="feature">&#128269; Header Scan</div><div class="feature">&#128202; Scan History</div></div></div>`;

function authPage(title, fields, button, onsubmit) {
  app.innerHTML = `<div class="auth-grid">${hero}<div class="auth-card"><h2>${title}</h2></div></div>`;
  document.querySelector('.auth-card').appendChild(form(fields, button, onsubmit));
}

function loginPage() {
  authPage('เข้าสู่ระบบ', [['Email', 'email', 'email'], ['Password', 'password', 'password']], 'Login', async b => {
    const d = await api('/auth/login', { method: 'POST', body: JSON.stringify(b) });
    setSession(d.accessToken, d.user); location.hash = '#dashboard';
  });
}
function registerPage() {
  authPage('สมัครสมาชิก', [['Username', 'username'], ['Email', 'email', 'email'], ['Password', 'password', 'password']], 'Register', async b => {
    await api('/auth/register', { method: 'POST', body: JSON.stringify(b) }); location.hash = '#login';
  });
}
function forgotPage() {
  app.innerHTML = '<h2>Forgot Password</h2>';
  app.appendChild(form([['Email', 'email', 'email']], 'Send Reset', async b => {
    const d = await api('/auth/forgot-password', { method: 'POST', body: JSON.stringify(b) });
    alert('Reset token (dev): ' + d.resetToken); location.hash = '#reset';
  }));
}
function resetPage() {
  app.innerHTML = '<h2>Reset Password</h2>';
  app.appendChild(form([['Token', 'token'], ['New Password', 'password', 'password']], 'Reset', async b => {
    await api('/auth/reset-password', { method: 'POST', body: JSON.stringify({ token: b.token, newPassword: b.password }) }); location.hash = '#login';
  }));
}

async function dashboardPage() {
  if (!currentUser) return loginPage();
  const scans = await api('/security/history');
  const s = scans.length ? Math.round(scans.reduce((a, x) => a + (x.score || 0), 0) / scans.length) : '-';
  app.innerHTML = `<div class="stats"><div class="stat"><span>Total Scans</span><b>${scans.length}</b></div><div class="stat"><span>Avg Score</span><b>${s}</b></div><div class="stat"><span>Role</span><b>${currentUser.role}</b></div></div><h2>Welcome ${currentUser.username}</h2><h3>My Scan History</h3>`;
  app.innerHTML += `<table><tr><th>URL</th><th>Score</th><th>Status</th><th>Date</th><th></th></tr>` +
    scans.map(s => `<tr><td>${s.url}</td><td>${s.score}</td><td>${s.status_code}</td><td>${new Date(s.created_at).toLocaleString()}</td><td><button class="danger" onclick="delScan(${s.id})">Delete</button></td></tr>`).join('') + '</table>';
}
window.delScan = async id => { if (confirm('Delete scan ' + id + '?')) { await api('/security/history/' + id, { method: 'DELETE' }); render(); } };

function scanPage() {
  if (!currentUser) return loginPage();
  app.innerHTML = '<h2>API Security Checker</h2>';
  const out = document.createElement('div');
  app.appendChild(form([['https://example.com', 'url']], 'Scan', async b => {
    out.innerHTML = 'Scanning...';
    const d = await api('/security/check', { method: 'POST', body: JSON.stringify(b) });
    out.innerHTML = `<div class="card"><h3>Score: ${d.score}/100 (${d.statusCode})</h3><table><tr><th>Header</th><th>Status</th><th>Message</th></tr>` +
      d.findings.map(f => `<tr><td>${f.header}</td><td><span class="badge ${f.status}">${f.status}</span></td><td>${f.message}</td></tr>`).join('') + '</table></div>';
  }));
  app.appendChild(out);
}

async function profilePage() {
  if (!currentUser) return loginPage();
  app.innerHTML = '<h2>Profile</h2>';
  const me = await api('/users/profile');
  app.innerHTML += `<p>${me.email} — ${me.role} — joined ${new Date(me.created_at).toLocaleDateString()}</p>`;
  app.appendChild(form([['Username', 'username'], ['Email', 'email', 'email']], 'Update Profile', async b => {
    await api('/users/profile', { method: 'PUT', body: JSON.stringify(b) }); alert('Updated');
  }));
  document.querySelector('form input[name=username]').value = me.username;
  document.querySelector('form input[name=email]').value = me.email;
  app.appendChild(form([['Current Password', 'oldPassword', 'password'], ['New Password', 'newPassword', 'password']], 'Change Password', async b => {
    await api('/users/password', { method: 'PUT', body: JSON.stringify(b) }); alert('Changed');
  }));
}

async function adminPage() {
  if (!currentUser || currentUser.role !== 'admin') return dashboardPage();
  app.innerHTML = '<h2>Admin Dashboard</h2>';
  const d = await api('/admin/dashboard');
  app.innerHTML += `<div class="stats"><div class="stat"><span>Users</span><b>${d.users}</b></div><div class="stat"><span>Scans</span><b>${d.scans}</b></div><div class="stat"><span>Avg Score</span><b>${d.avgScore}</b></div><div class="stat"><span>Today</span><b>${d.scansToday}</b></div></div>`;
  const users = await api('/admin/users');
  app.innerHTML += '<h3>Users</h3><table><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th></th></tr>' +
    users.map(u => `<tr><td>${u.id}</td><td>${u.username}</td><td>${u.email}</td><td>${u.role}</td><td>${u.role === 'user' ? `<button class="danger" onclick="delUser(${u.id})">Delete</button>` : ''}</td></tr>`).join('') + '</table>';
  const scansAll = await api('/admin/scans');
  app.innerHTML += '<h3>All Scans</h3><table><tr><th>ID</th><th>User</th><th>URL</th><th>Score</th><th>Date</th><th></th></tr>' +
    scansAll.map(s => `<tr><td>${s.id}</td><td>${s.email}</td><td>${s.url}</td><td>${s.score}</td><td>${new Date(s.created_at).toLocaleString()}</td><td><button class="danger" onclick="delAdminScan(${s.id})">Delete</button></td></tr>`).join('') + '</table>';
  const logs = await api('/admin/logs');
  app.innerHTML += '<h3>Security Logs</h3><table><tr><th>Action</th><th>User</th><th>IP</th><th>Time</th></tr>' +
    logs.slice(0, 50).map(l => `<tr><td>${l.action}</td><td>${l.email || l.user_id || '-'}</td><td>${l.ip_address || ''}</td><td>${new Date(l.created_at).toLocaleString()}</td></tr>`).join('') + '</table>';
}
window.delUser = async id => { if (confirm('Delete user ' + id + '?')) { await api('/admin/users/' + id, { method: 'DELETE' }); render(); } };
window.delAdminScan = async id => { if (confirm('Delete scan ' + id + '?')) { await api('/admin/scans/' + id, { method: 'DELETE' }); render(); } };

render();
