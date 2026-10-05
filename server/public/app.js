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

function loginPage() {
  app.innerHTML = '<h2>Login</h2>';
  app.appendChild(form([['Email', 'email', 'email'], ['Password', 'password', 'password']], 'Login', async b => {
    const d = await api('/auth/login', { method: 'POST', body: JSON.stringify(b) });
    setSession(d.accessToken, d.user); location.hash = '#dashboard';
  }));
}
function registerPage() {
  app.innerHTML = '<h2>Register</h2>';
  app.appendChild(form([['Username', 'username'], ['Email', 'email', 'email'], ['Password', 'password', 'password']], 'Register', async b => {
    await api('/auth/register', { method: 'POST', body: JSON.stringify(b) }); location.hash = '#login';
  }));
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
  app.innerHTML = `<h2>Welcome ${currentUser.username} (${currentUser.role})</h2><h3>My Scan History</h3>`;
  const scans = await api('/security/history');
  app.innerHTML += `<table><tr><th>URL</th><th>Score</th><th>Status</th><th>Date</th></tr>` +
    scans.map(s => `<tr><td>${s.url}</td><td>${s.score}</td><td>${s.status_code}</td><td>${new Date(s.created_at).toLocaleString()}</td></tr>`).join('') + '</table>';
}

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
  app.innerHTML += `<div class="card">Users: ${d.users} | Scans: ${d.scans} | Avg score: ${d.avgScore}</div>`;
  const users = await api('/admin/users');
  app.innerHTML += '<h3>Users</h3><table><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th></th></tr>' +
    users.map(u => `<tr><td>${u.id}</td><td>${u.username}</td><td>${u.email}</td><td>${u.role}</td><td>${u.role === 'user' ? `<button class="danger" onclick="delUser(${u.id})">Delete</button>` : ''}</td></tr>`).join('') + '</table>';
  const logs = await api('/admin/logs');
  app.innerHTML += '<h3>Security Logs</h3><table><tr><th>Action</th><th>User</th><th>IP</th><th>Time</th></tr>' +
    logs.slice(0, 50).map(l => `<tr><td>${l.action}</td><td>${l.email || l.user_id || '-'}</td><td>${l.ip_address || ''}</td><td>${new Date(l.created_at).toLocaleString()}</td></tr>`).join('') + '</table>';
}
window.delUser = async id => { if (confirm('Delete user ' + id + '?')) { await api('/admin/users/' + id, { method: 'DELETE' }); render(); } };

render();
