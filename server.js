const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const AES_KEY = Buffer.from("ycb_floating_menu_key_256_bits_!", "utf8");
const AES_IV = Buffer.alloc(16, 0);

function aesEncrypt(plaintext) {
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

const app = express();
const PORT = process.env.PORT || 9999;
const DATA_FILE = path.join(__dirname, "data", "keys.json");

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "PINTU@2024#Secure!";
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");

function b64url_encode(buf) {
  return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64url_decode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64").toString();
}

function jwtSign(payload) {
  const header = b64url_encode(Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64url_encode(Buffer.from(JSON.stringify({ ...payload, iat: Date.now(), exp: Date.now() + 7200000 })));
  const sig = b64url_encode(crypto.createHmac("sha256", JWT_SECRET).update(header + "." + body).digest());
  return header + "." + body + "." + sig;
}

function jwtVerify(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const sig = b64url_encode(crypto.createHmac("sha256", JWT_SECRET).update(parts[0] + "." + parts[1]).digest());
    if (sig !== parts[2]) return null;
    const payload = JSON.parse(b64url_decode(parts[1]));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
}

app.use(cors({ origin: false }));
app.use(express.json());

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const store = {
  _data: null,
  load() {
    try {
      if (fs.existsSync(DATA_FILE))
        this._data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    } catch {}
    if (!this._data) {
      this._data = { keys: {}, nextId: 1 };
    }
    // Ensure users object exists (handles migration from old data file)
    if (!this._data.users) {
      this._data.users = {};
    }
    if (!this._data.users[ADMIN_USER]) {
      this._data.users[ADMIN_USER] = {
        password: crypto.createHash("sha256").update(ADMIN_PASS).digest("hex"),
        role: "admin",
      };
      this.save();
    }
    if (!this._data.keys["PINTU"]) {
      this._data.keys["PINTU"] = {
        licenseKey: "PINTU", deviceId: null,
        expiresAt: Date.now() + 365 * 86400000 * 100,
        isBlocked: false, createdAt: Date.now(), id: 1,
      };
      this.save();
    }
    return this;
  },
  save() {
    try { fs.writeFileSync(DATA_FILE, JSON.stringify(this._data, null, 2)); }
    catch (e) { console.error("Save error:", e.message); }
  },
  getKeys() { return Object.values(this._data.keys); },
  getKey(licenseKey) { return this._data.keys[licenseKey] || null; },
  addKey(licenseKey, durationDays) {
    const expiresAt = Date.now() + durationDays * 86400000;
    this._data.keys[licenseKey] = {
      licenseKey, deviceId: null, expiresAt,
      isBlocked: false, createdAt: Date.now(), id: this._data.nextId++,
    };
    this.save(); return this._data.keys[licenseKey];
  },
  updateDevice(licenseKey, deviceId) {
    const key = this._data.keys[licenseKey];
    if (!key) return null;
    key.deviceId = deviceId; this.save(); return key;
  },
};

store.load();

// Rate limiter for login
const loginAttempts = new Map();

function rateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + 900000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 900000; }
  entry.count++;
  loginAttempts.set(ip, entry);
  return entry;
}

function requireAuth(req, res, next) {
  const auth = req.headers["authorization"];
  const token = auth?.startsWith("Bearer ") ? auth.slice(7) : req.query["token"];
  if (!token) return res.status(401).json({ success: false, error: "Unauthorized" });
  const payload = jwtVerify(token);
  if (!payload) return res.status(401).json({ success: false, error: "Invalid or expired token" });
  req.user = payload;
  next();
}

function csrfProtect(req, res, next) { next(); }

// License validation
app.all(["/c", "/api/c", "/api/verify-license"], (req, res) => {
  const licenseKey = req.query.key || req.query.licenseKey || req.body?.key || req.body?.licenseKey;
  const deviceId = req.query.deviceId || req.body?.deviceId || req.body?.device;
  const finalKey = licenseKey || "PINTU";

  let keyData = store.getKey(finalKey);
  if (!keyData) {
    store.addKey(finalKey, 36500);
    keyData = store.getKey(finalKey);
  }

  if (keyData.isBlocked)
    return res.json({ success: false, status: "blocked", message: "License key is blocked" });
  if (Date.now() > keyData.expiresAt)
    return res.json({ success: false, status: "expired", message: "License key has expired" });

  if (deviceId && !keyData.deviceId) store.updateDevice(finalKey, deviceId);

  const plainJson = JSON.stringify({
    success: true, status: "active", licenseKey: finalKey,
    deviceId: keyData.deviceId || deviceId || "unbound",
    expiresAt: new Date(keyData.expiresAt).toISOString(),
    validationTimestamp: new Date().toISOString(),
  });

  res.type("text/plain").send(aesEncrypt(plainJson));
});

// ===== AUTH API =====
function doLogin(username, password) {
  if (!username || !password) return { success: false, error: "Username and password required" };
  const user = store._data.users[username];
  if (!user || user.password !== crypto.createHash("sha256").update(password).digest("hex"))
    return { success: false, error: "Invalid credentials" };
  const token = jwtSign({ username, role: user.role });
  return { success: true, token, expiresIn: 7200 };
}

app.post("/api/auth/login", (req, res) => {
  const ip = req.ip || req.connection?.remoteAddress || "unknown";
  const rl = rateLimit(ip);
  if (rl.count > 5)
    return res.json({ success: false, error: "Too many attempts. Try again in 15 min." });
  res.json(doLogin(req.body?.username, req.body?.password));
});

app.post("/api/auth/login-form", express.urlencoded({ extended: true }), (req, res) => {
  const ip = req.ip || req.connection?.remoteAddress || "unknown";
  const rl = rateLimit(ip);
  if (rl.count > 5) return res.redirect("/?error=rate_limit");
  const result = doLogin(req.body?.username, req.body?.password);
  if (!result.success) return res.redirect("/?error=invalid");
  res.redirect("/?token=" + result.token);
});

app.get("/api/auth/check", requireAuth, (req, res) => {
  res.json({ success: true, username: req.user.username, role: req.user.role });
});

// ===== ADMIN API (protected) =====
app.get("/api/admin/get-licenses", requireAuth, (req, res) => {
  res.json({ success: true, licenses: store.getKeys() });
});

app.post("/api/admin/create-key", requireAuth, csrfProtect, (req, res) => {
  const { licenseKey, durationDays } = req.body;
  const key = licenseKey || (() => {
    const s = () => crypto.randomBytes(2).toString("hex").toUpperCase();
    return `KEY-${s()}-${s()}-${s()}`;
  })();
  const created = store.addKey(key, parseInt(durationDays) || 30);
  res.json({ success: true, license: created });
});

app.post("/api/admin/block-key", requireAuth, csrfProtect, (req, res) => {
  const { licenseKey, isBlocked } = req.body;
  const key = store.getKey(licenseKey);
  if (!key) return res.status(404).json({ success: false, error: "Key not found" });
  key.isBlocked = isBlocked; store.save();
  res.json({ success: true, license: key });
});

app.post("/api/admin/delete-key", requireAuth, csrfProtect, (req, res) => {
  const { licenseKey } = req.body;
  if (store._data.keys[licenseKey]) {
    delete store._data.keys[licenseKey]; store.save();
    res.json({ success: true });
  } else res.status(404).json({ success: false, error: "Key not found" });
});

// ===== Admin Panel UI =====
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>C2 Admin Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e0e0;font-family:'Segoe UI',sans-serif;min-height:100vh}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;
  background:radial-gradient(ellipse at center,#1a1a2e,#0a0a0f)}
.login-box{background:#12121a;border:1px solid #2a2a3e;border-radius:16px;padding:40px;
  width:380px;box-shadow:0 0 40px rgba(255,51,51,0.1)}
.login-box h1{color:#ff3333;font-size:24px;margin-bottom:8px;text-align:center}
.login-box p{color:#888;text-align:center;margin-bottom:30px;font-size:14px}
.login-box input{width:100%;padding:12px 16px;margin-bottom:16px;background:#1a1a26;
  border:1px solid #2a2a3e;border-radius:8px;color:#e0e0e0;font-size:14px;transition:border .2s}
.login-box input:focus{outline:none;border-color:#ff3333}
.login-box button{width:100%;padding:12px;background:#ff3333;color:#fff;border:none;
  border-radius:8px;font-size:16px;cursor:pointer;transition:background .2s}
.login-box button:hover{background:#cc0000}
.login-box .error{color:#ff3333;font-size:13px;text-align:center;margin-top:12px;display:none}
.dashboard{display:none;padding:20px;max-width:1000px;margin:auto}
.header{display:flex;justify-content:space-between;align-items:center;padding:20px 0;
  border-bottom:1px solid #2a2a3e;margin-bottom:30px}
.header h1{color:#ff3333;font-size:22px}
.header .user-info{display:flex;align-items:center;gap:16px;font-size:14px;color:#888}
.header .logout-btn{padding:8px 20px;background:transparent;border:1px solid #ff3333;
  color:#ff3333;border-radius:6px;cursor:pointer;font-size:13px;transition:all .2s}
.header .logout-btn:hover{background:#ff3333;color:#fff}
.card{background:#12121a;border:1px solid #2a2a3e;border-radius:12px;padding:24px;margin-bottom:24px}
.card h3{font-size:16px;margin-bottom:16px;color:#ccc}
.form-row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.form-row select,.form-row input{flex:1;min-width:140px;padding:10px 14px;background:#1a1a26;
  border:1px solid #2a2a3e;border-radius:8px;color:#e0e0e0;font-size:14px}
.form-row select:focus,.form-row input:focus{outline:none;border-color:#ff3333}
.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 24px;background:#ff3333;
  color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;transition:background .2s;
  white-space:nowrap}
.btn:hover{background:#cc0000}
.btn-sm{padding:6px 14px;font-size:12px}
.btn-danger{background:#661111}
.btn-danger:hover{background:#991111}
.btn-success{background:#116611}
.btn-success:hover{background:#119911}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 8px;font-size:12px;color:#666;text-transform:uppercase;
  letter-spacing:0.5px;border-bottom:1px solid #2a2a3e}
td{padding:10px 8px;font-size:14px;border-bottom:1px solid #1a1a26}
.mono{font-family:'Cascadia Code','Fira Code',monospace;color:#ff9999;font-size:13px}
.badge{display:inline-block;padding:3px 10px;border-radius:10px;font-size:11px;font-weight:600}
.badge-active{background:#00ff6633;color:#00ff66}
.badge-blocked{background:#ff333333;color:#ff3333}
.badge-expired{background:#ff950033;color:#ff9500}
.badge-unused{background:#66666633;color:#999}
.action-cell{display:flex;gap:6px}
.toast{position:fixed;bottom:30px;right:30px;padding:14px 24px;border-radius:10px;font-size:14px;
  z-index:999;animation:slideIn .3s ease;display:none}
.toast-success{background:#116611;border:1px solid #22aa22;color:#aaffaa}
.toast-error{background:#661111;border:1px solid #aa2222;color:#ffaaaa}
@keyframes slideIn{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.empty-row td{text-align:center;padding:30px;color:#555;font-style:italic}
</style>
</head>
<body>
<div class="login-wrap" id="loginWrap">
  <div class="login-box">
    <h1>✦ C2 PANEL</h1>
    <p>License Management System</p>
    <form id="loginForm" action="/api/auth/login-form" method="POST">
      <input type="text" name="username" placeholder="Username" autocomplete="off" id="username" required>
      <input type="password" name="password" placeholder="Password" id="password" required>
      <button type="submit" id="signInBtn">Sign In</button>
    </form>
    <div class="error" id="loginError">Invalid credentials</div>
    <div class="error" id="loginErrorForm" style="display:block;color:#ff9500">__ERROR_MSG__</div>
  </div>
</div>

<div class="dashboard" id="dashboard">
  <div class="header">
    <h1>✦ C2 PANEL</h1>
    <div class="user-info">
      <span id="userDisplay">admin</span>
      <button class="logout-btn" onclick="logout()">Sign Out</button>
    </div>
  </div>

  <div class="card">
    <h3>Create License Key</h3>
    <div class="form-row">
      <select id="days">
        <option value="7">7 Days</option>
        <option value="30">30 Days</option>
        <option value="365" selected>365 Days</option>
        <option value="3650">Permanent</option>
      </select>
      <input type="text" id="customKey" placeholder="Custom key (blank = random)">
      <button class="btn" onclick="createKey()">+ Create</button>
    </div>
  </div>

  <div class="card">
    <h3>License Keys</h3>
    <table>
      <thead><tr>
        <th>License Key</th><th>Device ID</th><th>Status</th><th>Created</th><th>Actions</th>
      </tr></thead>
      <tbody id="keysBody"><tr><td colspan="5" class="empty-row">Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let TOKEN = null, CSRF = null;

async function api(method, path, body) {
  try {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (TOKEN) opts.headers['Authorization'] = 'Bearer ' + TOKEN;
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    return await res.json();
  } catch(e) {
    return { success: false, error: 'Network error: ' + e.message };
  }
}

function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast toast-' + type;
  t.style.display = 'block';
  setTimeout(() => { t.style.display = 'none'; }, 3000);
}

async function logout() {
  TOKEN = null; CSRF = null;
  document.getElementById('loginWrap').style.display = 'flex';
  document.getElementById('dashboard').style.display = 'none';
}

async function loadKeys() {
  const d = await api('GET', '/api/admin/get-licenses');
  if (!d.success) return;
  const tbody = document.getElementById('keysBody');
  if (!d.licenses?.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No license keys found</td></tr>';
    return;
  }
  tbody.innerHTML = d.licenses.map(k => {
    let status = 'unused', badge = 'badge-unused';
    if (k.isBlocked) { status = 'blocked'; badge = 'badge-blocked'; }
    else if (k.expiresAt < Date.now()) { status = 'expired'; badge = 'badge-expired'; }
    else if (k.deviceId) { status = 'active'; badge = 'badge-active'; }
    const created = new Date(k.createdAt).toLocaleDateString();
    const expires = new Date(k.expiresAt).toLocaleDateString();
    return '<tr><td class="mono">' + k.licenseKey + '</td>' +
      '<td class="mono">' + (k.deviceId || '<i style="color:#555">unbound</i>') + '</td>' +
      '<td><span class="badge ' + badge + '">' + status + '</span></td>' +
      '<td style="color:#888;font-size:13px">' + created + '</td>' +
      '<td class="action-cell">' +
      (!k.isBlocked
        ? '<button class="btn btn-sm btn-danger" onclick="blockKey(\'' + k.licenseKey + '\')">Block</button>'
        : '<button class="btn btn-sm btn-success" onclick="unblockKey(\'' + k.licenseKey + '\')">Unblock</button>') +
      '<button class="btn btn-sm btn-danger" onclick="deleteKey(\'' + k.licenseKey + '\')">Delete</button></td></tr>';
  }).join('');
}

async function createKey() {
  const d = await api('POST', '/api/admin/create-key', {
    licenseKey: document.getElementById('customKey').value.trim() || undefined,
    durationDays: parseInt(document.getElementById('days').value),
  });
  if (d.success) { showToast('Key: ' + d.license.licenseKey, 'success'); loadKeys(); }
  else showToast(d.error, 'error');
}

async function blockKey(k) {
  const d = await api('POST', '/api/admin/block-key', { licenseKey: k, isBlocked: true });
  if (d.success) { showToast('Key blocked', 'success'); loadKeys(); }
}

async function unblockKey(k) {
  const d = await api('POST', '/api/admin/block-key', { licenseKey: k, isBlocked: false });
  if (d.success) { showToast('Key unblocked', 'success'); loadKeys(); }
}

async function deleteKey(k) {
  if (!confirm('Delete key ' + k + '?')) return;
  const d = await api('POST', '/api/admin/delete-key', { licenseKey: k });
  if (d.success) { showToast('Key deleted', 'success'); loadKeys(); }
}

// Intercept form submission with JS (falls back to form POST if JS fails)
document.getElementById('loginForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const btn = document.getElementById('signInBtn');
  btn.disabled = true; btn.textContent = 'Signing in...';
  const err = document.getElementById('loginError');
  const u = document.getElementById('username').value.trim();
  const p = document.getElementById('password').value;
  if (!u || !p) { err.textContent = 'Fill all fields'; err.style.display = 'block'; btn.disabled = false; btn.textContent = 'Sign In'; return; }
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    });
    const d = await res.json();
    if (!d.success) { err.textContent = d.error; err.style.display = 'block'; btn.disabled = false; btn.textContent = 'Sign In'; return; }
    err.style.display = 'none';
    TOKEN = d.token;
    document.getElementById('loginWrap').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    document.getElementById('userDisplay').textContent = u;
    showToast('Logged in', 'success');
    loadKeys();
  } catch(e) {
    // Fallback: submit form normally
    this.submit();
  }
});

// Auto-login if token in URL
const urlToken = new URLSearchParams(window.location.search).get('token');
if (urlToken) {
  TOKEN = urlToken;
  document.getElementById('loginWrap').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';
  document.getElementById('userDisplay').textContent = 'admin';
  loadKeys();
}
</script>
</body>
</html>`;

app.get("/", (req, res) => {
  const errors = { rate_limit: "Too many attempts. Try again later.", empty: "Fill all fields", invalid: "Invalid credentials" };
  const errorMsg = errors[req.query.error] || "";
  res.type("html").send(ADMIN_HTML.replace("__ERROR_MSG__", errorMsg));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`C2 Server on port ${PORT}`);
});
