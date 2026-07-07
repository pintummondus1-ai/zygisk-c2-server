# Zygisk C2 Server - Deploy Guide

## Quick Deploy (Render - Free, Recommended)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=<your-repo-url>)

1. Go to https://dashboard.render.com
2. Click "New +" → "Web Service"
3. Connect your GitHub repo OR use "Public Git Repository"
4. Paste this: `https://github.com/YOUR_USERNAME/zygisk-c2-server`
5. Or just upload the `deploy/` folder as a new repo

**Settings:**
- Name: `zygisk-c2-server`
- Runtime: `Node`
- Build Command: `npm install`
- Start Command: `node server.js`
- Plan: **Free**

**Environment Variable (optional):**
- `ADMIN_TOKEN` = your-secret-token (default: `admin123`)

Once deployed, you get: `https://zygisk-c2-server.onrender.com`

---

## Deploy to Vercel

1. Upload the `deploy/` folder to a GitHub repo
2. Go to https://vercel.com → Import repo
3. Framework: `Other`
4. Root Directory: `deploy/`
5. Build: `npm install`
6. Output: `server.js`
7. Env: `ADMIN_TOKEN` = your-secret-token

Note: Keys stored in memory (lost on redeploy). For persistence, add Vercel KV.

---

## Deploy to Railway

1. Upload `deploy/` folder to GitHub
2. Go to https://railway.app
3. New Project → Deploy from GitHub repo
4. Root: `deploy/`
5. Start: `node server.js`

---

## After Deploying

Your server URL: `https://your-app-name.onrender.com`

### Test it:
```bash
# Validate your key
curl "https://your-app-name.onrender.com/c?key=KEY-EWCP-AYAG-19YU"

# Create a new key (admin)
curl -X POST "https://your-app-name.onrender.com/api/admin/create-key" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: admin123" \
  -d '{"durationDays": 365}'

# List all keys
curl "https://your-app-name.onrender.com/api/admin/get-licenses?adminToken=admin123"
```

### Admin Dashboard:
Open `https://your-app-name.onrender.com/` in browser.
Admin Token: `admin123`

---

## Point Module to Your Server

Edit the `service.sh` in the module ZIP:

Replace `vercellicenseapi.vercel.app` with `your-app-name.onrender.com`:

```sh
# Instead of:
# CLASSPATH=... com.floatingmenu.VercelPoller

# Just change the hosts redirect:
echo "YOUR_SERVER_IP your-app-name.onrender.com" >> /system/etc/hosts
```

Or if you want ALL requests to go through your server, edit the module's DEX
to change the endpoint URL (requires recompiling).
