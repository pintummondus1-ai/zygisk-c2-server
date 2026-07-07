const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// AES key from the DEX: 32 bytes for AES-256
const AES_KEY = Buffer.from("ycb_floating_menu_key_256_bits_!", "utf8");
const AES_IV = Buffer.alloc(16, 0); // 16 zero bytes

function aesEncrypt(plaintext) {
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

const app = express();
const PORT = process.env.PORT || 9999;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "admin123";
const DATA_FILE = path.join(__dirname, "data", "keys.json");

app.use(cors());
app.use(express.json());

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const store = {
  _data: null,
  load() {
    try {
      if (fs.existsSync(DATA_FILE)) {
        this._data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
      }
    } catch {}
    if (!this._data) {
      this._data = { keys: {}, nextId: 1 };
      // Auto-create PINTU key on first run
      this._data.keys["PINTU"] = {
        licenseKey: "PINTU",
        deviceId: null,
        expiresAt: Date.now() + 365 * 86400000 * 100,
        isBlocked: false,
        createdAt: Date.now(),
        id: 1,
      };
    }
    return this;
  },
  save() {
    try {
      fs.writeFileSync(DATA_FILE, JSON.stringify(this._data, null, 2));
    } catch (e) { console.error("Save error:", e.message); }
  },
  getKeys() { return Object.values(this._data.keys); },
  getKey(licenseKey) { return this._data.keys[licenseKey] || null; },
  addKey(licenseKey, durationDays) {
    const expiresAt = Date.now() + durationDays * 86400000;
    this._data.keys[licenseKey] = {
      licenseKey, deviceId: null, expiresAt,
      isBlocked: false, createdAt: Date.now(),
      id: this._data.nextId++,
    };
    this.save();
    return this._data.keys[licenseKey];
  },
  updateDevice(licenseKey, deviceId) {
    const key = this._data.keys[licenseKey];
    if (!key) return null;
    key.deviceId = deviceId; this.save(); return key;
  },
};

store.load();

function generateKey() {
  const seg1 = crypto.randomBytes(2).toString("hex").toUpperCase();
  const seg2 = crypto.randomBytes(2).toString("hex").toUpperCase();
  const seg3 = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `KEY-${seg1}-${seg2}-${seg3}`;
}

function auth(req, res, next) {
  const token = req.headers["x-admin-token"] || req.query.adminToken;
  if (token !== ADMIN_TOKEN) return res.status(401).json({ success: false, error: "Unauthorized" });
  next();
}

// License validation endpoint - called by the Zygisk module
app.all(["/c", "/api/c", "/api/verify-license"], (req, res) => {
  const licenseKey = req.query.key || req.query.licenseKey || req.body?.key || req.body?.licenseKey;
  const deviceId = req.query.deviceId || req.body?.deviceId || req.body?.device;
  const finalKey = licenseKey || "PINTU";
  
  let keyData = store.getKey(finalKey);
  if (!keyData) {
    store.addKey(finalKey, 36500);
    keyData = store.getKey(finalKey);
  }
  
  if (keyData.isBlocked) {
    return res.json({ success: false, status: "blocked", message: "License key is blocked" });
  }
  if (Date.now() > keyData.expiresAt) {
    return res.json({ success: false, status: "expired", message: "License key has expired" });
  }
  
  if (deviceId && !keyData.deviceId) store.updateDevice(finalKey, deviceId);
  
  const plainJson = JSON.stringify({
    success: true,
    status: "active",
    licenseKey: finalKey,
    deviceId: keyData.deviceId || deviceId || "unbound",
    expiresAt: new Date(keyData.expiresAt).toISOString(),
    validationTimestamp: new Date().toISOString(),
  });
  
  // Encrypt response with AES/CBC/PKCS5Padding (module expects encrypted response)
  const encrypted = aesEncrypt(plainJson);
  res.type("text/plain").send(encrypted);
});

// Admin API
app.get("/api/admin/get-licenses", auth, (req, res) => {
  res.json({ success: true, licenses: store.getKeys() });
});

app.post("/api/admin/create-key", auth, (req, res) => {
  const { licenseKey, durationDays } = req.body;
  const key = licenseKey || generateKey();
  const created = store.addKey(key, parseInt(durationDays) || 30);
  res.json({ success: true, license: created });
});

app.post("/api/admin/block-key", auth, (req, res) => {
  const { licenseKey, isBlocked } = req.body;
  const key = store.getKey(licenseKey);
  if (!key) return res.status(404).json({ success: false, error: "Key not found" });
  key.isBlocked = isBlocked; store.save();
  res.json({ success: true, license: key });
});

app.post("/api/admin/delete-key", auth, (req, res) => {
  const { licenseKey } = req.body;
  if (store._data.keys[licenseKey]) {
    delete store._data.keys[licenseKey]; store.save();
    res.json({ success: true });
  } else res.status(404).json({ success: false, error: "Key not found" });
});

// Admin Panel UI
app.get("/", (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><title>Zygisk C2 Server</title>
<style>
body{background:#111;color:#eee;font-family:sans-serif;padding:20px;max-width:800px;margin:auto}
h1{color:#ff3333;border-bottom:1px solid #333;padding-bottom:10px}
.card{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:20px;margin:20px 0}
input,select{width:100%;padding:10px;margin:10px 0;background:#222;border:1px solid #444;color:#eee;border-radius:4px}
button{padding:10px 20px;background:#ff3333;color:white;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#cc0000}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{padding:8px;text-align:left;border-bottom:1px solid #333}
.mono{font-family:monospace;color:#ff9999}
.badge{padding:3px 8px;border-radius:4px;font-size:12px}
.active{background:#00ff6633;color:#00ff66}
.blocked{background:#ff333333;color:#ff3333}
.expired{background:#ff950033;color:#ff9500}
</style></head><body>
<h1>Zygisk C2 Server</h1>
<div class="card">
<p><strong>Your Server URL:</strong> <span class="mono" id="surl">loading...</span></p>
<p><strong>Admin Token:</strong> <span class="mono">${ADMIN_TOKEN}</span></p>
<p><strong>Validation Endpoint:</strong> <span class="mono">/api/verify-license?key=PINTU</span></p>
</div>
<div class="card">
<h3>Create License Key</h3>
<select id="days">
<option value="30">30 Days</option><option value="365" selected>365 Days</option>
<option value="3650">Permanent</option>
</select>
<input type="text" id="customKey" placeholder="Custom key (blank = random)">
<button onclick="createKey()">Create Key</button>
</div>
<div class="card">
<h3>Licenses</h3>
<table><thead><tr><th>Key</th><th>Device</th><th>Status</th><th>Action</th></tr></thead>
<tbody id="keysBody"><tr><td colspan="4">Loading...</td></tr></tbody></table>
</div>
<script>
document.getElementById('surl').textContent = window.location.origin;
async function api(p,o={}){return(await fetch(p,{headers:{'Content-Type':'application/json',...o.headers},...o})).json()}
async function loadKeys(){
  const d=await api('/api/admin/get-licenses?adminToken=${ADMIN_TOKEN}');
  document.getElementById('keysBody').innerHTML = d.licenses?.length
    ? d.licenses.map(k=>{
        let s='unused',c='active';
        if(k.isBlocked){s='blocked';c='blocked'}
        else if(k.expiresAt<Date.now()){s='expired';c='expired'}
        else if(k.deviceId){s='active';c='active'}
        return '<tr><td class="mono">'+k.licenseKey+
          '</td><td class="mono">'+(k.deviceId||'<i>unbound</i>')+
          '</td><td><span class="badge '+c+'">'+s+'</span></td><td>'+
          '<button onclick="delKey(\\''+k.licenseKey+'\\')">Delete</button></td></tr>';
      }).join('') : '<tr><td colspan="4">No keys</td></tr>';
}
async function createKey(){
  const d=await api('/api/admin/create-key',{method:'POST',
    headers:{'X-Admin-Token':'${ADMIN_TOKEN}'},
    body:JSON.stringify({licenseKey:document.getElementById('customKey').value||undefined,
      durationDays:parseInt(document.getElementById('days').value)})
  });
  if(d.success){alert('Key created: '+d.license.licenseKey);loadKeys()}
}
async function delKey(k){
  if(!confirm('Delete '+k+'?'))return;
  await api('/api/admin/delete-key',{method:'POST',
    headers:{'X-Admin-Token':'${ADMIN_TOKEN}'},
    body:JSON.stringify({licenseKey:k})
  });loadKeys();
}
loadKeys();
</script></body></html>`);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`C2 Server on port ${PORT}`);
  console.log(`Admin token: ${ADMIN_TOKEN}`);
  console.log(`Verify:  GET /c?key=PINTU`);
  console.log(`Panel:   GET /`);
});
