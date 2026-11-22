# SecureScan AI — Production Deployment Guide & Mobile PWA Setup

This guide provides step-by-step instructions to deploy **SecureScan AI** to production and configure it as an installable **Progressive Web App (PWA)** on mobile devices (Android and iOS).

---

## 📱 Mobile PWA Capabilities

SecureScan AI is configured as a fully installable Progressive Web App:
- **Instant Install Banner:** When opening the website link on any smartphone or browser, a native install banner automatically slides in.
- **Standalone Mobile Mode:** Once installed, SecureScan launches in full-screen mode without browser address bars, tabs, or navigation clutter.
- **Responsive Layout:** Optimized touch targets (minimum 44px), zero horizontal scrolling/overflow, horizontal scrollable filter chips, and full-width drawer modals.
- **Offline Shell & Fast Caching:** Service worker (`sw.js`) caches app shell, logos, and icons for instantaneous launch.

### How to Install on Mobile Devices

#### 🤖 Android (Google Chrome, Edge, Brave, Samsung Internet)
1. Open the project URL in your mobile browser.
2. A bottom install card will automatically pop up: **"Install SecureScan AI"**.
3. Tap **"Install App"**.
4. Alternatively, tap the browser menu (three dots `⋮`) and select **"Install app"** or **"Add to Home screen"**.
5. The SecureScan AI shield icon will appear directly on your home screen and app drawer.

#### 🍏 iOS / iPhone / iPad (Safari)
1. Open the project URL in **Safari**.
2. Tap the **Share** button (box with an arrow pointing up `⎋`) at the bottom of the screen.
3. Scroll down and tap **"Add to Home Screen"** (`⊕`).
4. Tap **"Add"** in the top-right corner.
5. The SecureScan AI app is now on your home screen and opens like an iOS native app.

---

## 🚀 Deployment Options

SecureScan AI can be deployed using either:
- **Option A (Recommended): Docker Compose Full-Stack** (Fastest, zero configuration, runs on any VPS/Cloud VM).
- **Option B: Split Cloud PaaS (Vercel Frontend + Render/Railway Backend)**.

---

### Option A: Docker Compose Deployment (Single Server / VPS)

Ideal for AWS EC2, DigitalOcean, Linode, Hetzner, or any Linux server with Docker.

#### 1. Server Prerequisites
Install Docker and Docker Compose on your server:
```bash
# Ubuntu / Debian
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

#### 2. Clone Repository
```bash
git clone https://github.com/CyberFocus2410/SecureScan.git
cd SecureScan
```

#### 3. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` and configure production secrets:
```env
ENVIRONMENT=production
DEBUG=false
POSTGRES_USER=securescan
POSTGRES_PASSWORD=your_super_strong_postgres_password
POSTGRES_DB=securescan
WEBHOOK_SECRET=your_random_secret_token
```

#### 4. Build and Start Services
```bash
docker compose up -d --build
```

#### 5. Verify Running Services
```bash
docker compose ps
```
You should see 5 healthy containers running:
- `securescan-web` (NGINX + React PWA on port 80/3000)
- `securescan-api` (FastAPI backend on port 8000)
- `securescan-worker` (Async scan task runner)
- `securescan-postgres` (PostgreSQL 16)
- `securescan-redis` (Redis 7)

#### 6. Access Application
- Web App / PWA: `http://<your-server-ip>:3000` or `http://<your-domain>`
- API Docs: `http://<your-server-ip>:8000/docs`
- Health Check: `http://<your-server-ip>:8000/api/v1/health`

---

### Option B: Cloud PaaS Deployment (Vercel + Render / Railway)

If you prefer serverless/managed platforms without managing Docker VMs:

#### Step 1: Deploy Backend (Render or Railway)
1. Fork or push your SecureScan repository to GitHub.
2. Go to [Render.com](https://render.com) or [Railway.app](https://railway.app).
3. Create a **New Web Service** pointing to your repository.
4. Set **Root Directory** to `backend`.
5. Set **Build Command:** `./build.sh` (or `pip install --prefer-binary -r requirements.txt`).
6. Set **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
7. Add a managed **PostgreSQL** database and a managed **Redis** instance in Render/Railway (or use SQLite/in-memory for zero-dependency test deploys).
8. Add Environment Variables in the Render Dashboard (**CRITICAL**):
   - **`PYTHON_VERSION`**: `3.11.9` *(Mandatory: Prevents Render from defaulting to Python 3.14 which lacks pre-built wheels for pydantic-core)*
   - **`PIP_PREFER_BINARY`**: `1`
   - `DATABASE_URL`: `sqlite:///./securescan_dev.db` (or your internal PostgreSQL URL)
   - `REDIS_URL`: Connection string from your managed Redis instance
   - `CORS_ORIGINS`: `["https://securescanbox.xyz","https://www.securescanbox.xyz","https://secure-scan-two.vercel.app","http://localhost:3000"]`
   - `CORS_ORIGIN_REGEX`: `^https?:\/\/(localhost|127\.0\.0\.1|.*\.vercel\.app|(.*\.)?securescanbox\.xyz)(:\d+)?$`
   - `ENVIRONMENT`: `production`
   - `DEBUG`: `false`
   - `SANDBOX_ALLOW_HOSTED_SUBPROCESS`: `true` *(Enables execution of pinned primary security tool CLIs inside Render's isolated PaaS container)*
   - `SANDBOX_BACKEND`: `hosted-container`
   - `WEBHOOK_SECRET`: `your_random_hmac_secret_key`

> [!TIP]
> You can also paste the contents of `render.env.example` directly into Render Dashboard via **Environment -> Add from .env** for instant one-click configuration.

#### Step 2: Deploy Frontend (Vercel)
1. Go to [Vercel.com](https://vercel.com) and click **"Add New Project"**.
2. Select your `SecureScan` repository.
3. Configure the Project Settings:
   - **Root Directory:** `frontend`
   - **Framework Preset:** `Vite`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. Add Environment Variable:
   - `VITE_API_URL`: `https://securescan-f6is.onrender.com` (or your actual Render backend URL)
5. Click **Deploy**.
6. When Vercel finishes building, you will receive an HTTPS URL (e.g., `https://secure-scan-two.vercel.app` or your custom domain `https://securescanbox.xyz`).
7. Open this URL in any mobile browser or desktop to use the application!

---

## 🔒 Production Security Checklist

Before public launch:
- [x] Rate limiting active (120 req/min/IP via [rate_limit.py](backend/app/core/rate_limit.py))
- [x] Strict security headers enabled (HSTS, CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff via [security_headers.py](backend/app/core/security_headers.py) & NGINX)
- [x] SSRF-safe GitHub cloning with IP blacklisting ([safe_fetch.py](backend/app/core/safe_fetch.py))
- [x] Secrets redacted at parser boundary before storage ([security.py](backend/app/core/security.py))
- [x] PWA manifest and service worker precaching active ([manifest.json](frontend/public/manifest.json) & [sw.js](frontend/public/sw.js))
- [x] Pure static analysis model: isolated static SAST/rules with zero code execution, zero exploit confirmation, and zero network calls during scan
- [x] Full mobile responsiveness verified across all viewport sizes
