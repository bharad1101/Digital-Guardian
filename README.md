# Digital Guardian

Personal cybersecurity assistant for inspecting suspicious **messages**, **links**,
**QR codes**, **screenshots** and **images** before you interact with them.

It provides a consistent experience across a desktop/mobile **website** and an
**Android-first mobile app**, both powered by a single shared **Flask API** and a
hybrid (rules + ML) threat-analysis engine.

> This is a real, working implementation — not a mockup. Every screen calls the
> same analysis service, results persist to history, analytics are derived from
> real stored scans, and automated tests cover the backend and client flows.

---

## 1. What it does

- **Guardian Lens** — QR security: scan with the camera, upload an image, select
  from the gallery, drag & drop, or paste a payload. The decoded payload is shown
  **before** anything opens, then analysed (URL structure, Wi-Fi, non-URL
  payloads) with explainable risks and recommendations.
- **Text / SMS / clipboard analysis** — paste a message, analyse from the share
  sheet on mobile, or use the explicit "Paste from clipboard" action. No
  background clipboard monitoring.
- **URL analysis** — passive structural inspection (scheme, host, IP literals,
  userinfo, ports, punycode, shorteners, suspicious TLDs/keywords, brand
  impersonation) with an SSRF-guarded, optional remote-inspection path that is
  disabled by default.
- **Image / screenshot analysis** — upload an image, extract any QR code and
  (when tesseract is installed) OCR text, run the extracted content through the
  same risk engine, and report the *source* of each finding.
- **Hybrid risk engine** — deterministic, explainable rule scoring combined with
  a trained SMS spam classifier (scikit-learn pipeline). The two evidence
  sources are reported separately; a low score is never presented as a
  guarantee of safety.
- **History & analytics** — private per-user scan history with search, filters,
  pagination, delete-one/delete-all, retention settings, and dashboard stats
  computed from the database.
- **Auth & privacy** — secure password hashing, CSRF for cookie sessions,
  signed Bearer tokens for the mobile app, user-local rate limits, ownership
  checks on every resource, upload validation, and a privacy notice. Images are
  processed in memory and never stored by default.

## 2. Architecture

```
                        ┌──────────────────────────────────────────┐
                        │              Shared Backend                │
                        │   Flask app (app.py)                      │
                        │   REST API under /api/v1                  │
                        │   Authentication  ·  Ownership checks     │
                        │   Threat analysis · Risk scoring          │
                        │   Scan history   · Analytics              │
                        │   Security headers · Rate limits · CSRF   │
                        └───────────────┬──────────────────────────┘
                                        │ same JSON schema
             ┌──────────────────────────┴──────────────────────────┐
             │                                                     │
    Responsive Web App                                   Expo (React Native) App
    - Dashboard / Lens / Scan          Android-first: camera QR, gallery,
    - Text & URL analysis                clipboard, deep-link share, history,
    - Image upload & OCR                 settings, notifications preferences
    - History / Analytics / Settings
```

Key directories:

```
app.py                 Application factory, security headers, error handlers, CLI.
config.py              Environment-based configuration (dev/test/prod).
extensions.py          Flask-SQLAlchemy / Migrate / Login / CSRF / Limiter wiring.
models.py              User, UserSettings, Scan (history) + helpers.
routes/
  web.py               Website page routes (dashboard, scanner, lens, history…).
  auth.py              Website login / register / logout.
  api.py               /api/v1 REST endpoints used by web JS + mobile.
services/
  analysis.py          Analysis orchestration (single entry point for all clients).
  threat_engine.py     Hybrid rule + ML risk scoring (documented method).
  ml_service.py        Loads ml/spam_model.pkl, graceful fallback.
  url_analyzer.py      Passive URL analysis + hardened SSRF fetch helper.
  qr_analyzer.py       QR payload classification + analysis.
  image_analyzer.py    Image validation, QR extraction, OCR wrapper.
  analytics.py         Real dashboard/history analytics from the database.
  validation.py        Server-side input validation.
  auth_tokens.py       Signed user tokens for the mobile app.
  responses.py         Unified analysis response schema + scan persistence.
ml/                   Dataset downloader, trainer, trained model artifact.
migrations/           Alembic/Flask-Migrate revisions.
templates/ static/    Website HTML/CSS/JS (vanilla JS + jsQR for QR decode).
tests/                Pytest backend tests.
wsgi.py               Production WSGI entry point.
mobile/               Expo (React Native) app, TypeScript, talks to /api/v1.
```

## 3. Tech stack

- Python 3.12+ (tested here on 3.14), Flask 3, Flask-SQLAlchemy, Flask-Migrate,
  Flask-Login, Flask-WTF (CSRF), Flask-Limiter.
- SQLite for local dev; PostgreSQL supported via `DATABASE_URL`.
- scikit-learn spam classifier (TF-IDF + balanced Logistic Regression).
- Pillow for image processing; `pytesseract` for OCR (requires the
  **tesseract** system binary); browser-side **jsQR** embedded for QR decode.
- Gunicorn for production WSGI.
- Expo SDK 57 / React Native 0.86 / React Navigation for the mobile app.

## 4. Backend setup

Prerequisites: Python 3.12+, `tesseract` installed at the OS level for OCR.

```bash
cd ~/Desktop/DigitalGuardian

# 1) Create and activate the virtual environment (use your project venv if present)
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/pip install -r requirements-dev.txt   # pytest

# 2) Configure environment
cp .env.example .env          # edit values; SECRET_KEY required in production

# 3) Database
./venv/bin/flask --app wsgi db upgrade
# or: ./venv/bin/flask --app app init-db   (create tables directly, no migrations)

# 4) Verify the ML model loads (optional but recommended)
./venv/bin/python -c "from services.ml_service import model_status; print(model_status())"

# 5) Run the development server
./venv/bin/flask --app wsgi run --debug
# or
./venv/bin/python wsgi.py
```

Open http://127.0.0.1:5000 in a browser.

## 5. Machine-learning model

The artifact is `ml/spam_model.pkl`, trained on the **SMS Spam Collection**
(UCI) dataset (`data/sms_spam_dataset.csv`, 5,160 rows, ~86% ham / ~14% spam).

- **Rebuild the dataset** (needs internet): `./venv/bin/python ml/download_dataset.py`
- **Retrain**: `./venv/bin/python ml/train_model.py`

The model is a `TfidfVectorizer` + balanced `LogisticRegression` pipeline
trained on a stratified 80/20 split (random_state 42). It is a traditional
machine-learning classifier — the UI and API describe it honestly as such, never
as a deep-learning system.

If the model file is missing or incompatible the app **fails gracefully**: rules
still run and every response explicitly notes the classifier was unavailable.

## 6. Unified analysis response

Every endpoint returns the same schema (optional fields are omitted when empty):

```json
{
  "success": true,
  "analysis_id": "…",
  "input_type": "text",
  "channel": "Message",
  "content": "…",
  "risk_score": 72,
  "rule_score": 65,
  "threat_level": "HIGH_RISK",
  "threat_level_label": "High Risk",
  "threat_type": "Phishing / Fraud",
  "scam_category": "Credential Theft",
  "ml_prediction": "SPAM",
  "ml_spam_probability": 91.5,
  "ml_available": true,
  "indicators": ["…"],
  "recommendations": ["…"],
  "manipulation": ["…"],
  "evidence": ["…"],
  "explanation": "…",
  "uncertainty": "…",
  "created_at": "…Z",
  "saved": true,
  "scan_id": 42
}
```

### Risk scoring (documented & deterministic)

- Each matched rule contributes fixed *rule points*; `rule_score =
  min(sum, 100)`.
- `risk_score = round(0.65 × rule_score + 0.35 × ml_spam_probability)`, with
  explicit overrides for high-confidence spam (≥85% → floor 65, ≥95% → floor 70)
  and for credential/banking bait (floor 75 / 85).
- Levels: `0–20 SAFE · ≤40 LOW_RISK · ≤60 SUSPICIOUS · ≤80 HIGH_RISK · >80 CRITICAL`.
- ML probability is **never** the sole measure of phishing or URL safety.
- Low scores always carry an uncertainty note: no known indicators ≠ safe.

## 7. API reference

Base path: `/api/v1`  ·  JSON both ways  ·  Errors: `{"success":false,"error","code"}`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | – | Create account (returns token + settings) |
| POST | `/auth/login` | – | Login (returns token + settings) |
| POST | `/auth/logout` | ✓ | Revoke current token + cookie session |
| GET | `/auth/me` | ✓ | Current user + settings |
| POST | `/analyze/text` | any | Analyse message text (`text`, `channel`) |
| POST | `/analyze/url` | any | Analyse a URL |
| POST | `/analyze/qr` | any | Analyse a decoded QR payload |
| POST | `/analyze/image` | any | Upload image (multipart `image`, optional `qr_payload`) |
| POST | `/analyze/screenshot` | any | Alias of image analysis |
| GET | `/history` | ✓ | Paginated history (`page`, `type`, `level`, `q`, `sort`) |
| GET | `/history/{id}` | ✓ | Single stored scan |
| DELETE | `/history/{id}` | ✓ | Delete one scan |
| DELETE | `/history` | ✓ | Delete all scans |
| GET | `/dashboard/summary` | ✓ | Real dashboard statistics |
| GET | `/analytics` | ✓ | Analytics overview (database-derived) |
| GET | `/settings` / `PATCH /settings` | ✓ | Privacy/settings read + update |
| GET | `/health`, `/capabilities` | – | Health + runtime capabilities |

Website routes (`/`, `/login`, `/register`, `/dashboard`, `/scanner`, `/lens`,
`/qr-scanner`, `/image`, `/history`, `/analytics`, `/settings`, `/privacy`) use
cookie sessions; the legacy `/api/analyze-qr` endpoint is preserved.

Upload limits: images capped at `MAX_CONTENT_LENGTH` (default 8 MB) and
`MAX_IMAGE_DIMENSION` (8000 px). URLs are inspected passively; network fetch is
off unless `ENABLE_REMOTE_URL_INSPECTION=true`.

## 8. Backend tests

```bash
./venv/bin/python -m pytest            # full suite
./venv/bin/python -m pytest -q --no-header
```

Suite coverage: startup, database/init, register/login, unauthorized access,
scan ownership, text/URL/QR/image analysis, bad inputs, rate limiting
helpers, analytics, delete + pagination, ML loading + fallback, and all page
routes.

## 9. Website

Vanilla HTML/CSS/JS (no framework). QR decoding uses the embedded jsQR library
with graceful messages when the browser has no camera, plus upload / drag-and-drop
and manual payload entry — the upload path never depends on the camera.

- Dark cybersecurity theme, accessible contrast, focus states, safe DOM
  construction (`textContent`) for untrusted payloads, reduced-motion support.
- Every visible control is functional; analytics and dashboards show real DB
  data (they show empty states when the database is empty).

## 10. Mobile app (Expo / React Native, Android-first)

A real mobile project under `mobile/` with TypeScript, React Navigation,
screens for Dashboard / Scan / Guardian Lens / History / Settings, camera QR
scanning, gallery import, clipboard paste, deep-link share handling and token
auth stored via `expo-secure-store`.

```bash
cd mobile
npm install

npm run typecheck          # tsc --noEmit
npx expo start             # Metro dev server (scan QR with Expo Go)
npm run android            # Android emulator / device
npm run ios                # iOS simulator (macOS only)
npx expo export --platform android   # validate JS bundling
```

### Important: the server address

`localhost` on a phone is the phone. Use **your computer's LAN IP** in the app's
Settings screen, e.g. `http://192.168.1.20:5000` (visible from Settings → Save
server address). The Android emulator uses `http://10.0.2.2:5000` by default
(out-of-box default in `app.json` → `extra.apiBaseUrl`). Update it in Settings
or via `app.json` for release builds.

### Sharing content into the app

- Deep links work now: `digitalguardian://share?text=<urlencoded>` or
  `…?url=<urlencoded>` open the app and run the analysis (an Android
  `VIEW` intent filter for the `digitalguardian://share` host is configured in
  `app.json`).
- **Android share-sheet** (`ACTION_SEND`) needs a native build with a share
  intent / extended native module (e.g. `expo-share-intent`). This is the
  documented external step and has not been built here (no device/emulator
  toolchain in this workspace). The deep-link path covers Expo Go and dev
  builds today.

### Mobile permissions (Android)

- `CAMERA` — only to scan QR codes you point the camera at. Not automatic.
- Photo library — only when you pick an image to analyse.
- Clipboard — read only via the explicit "Paste from clipboard" button.
- `INTERNET` — talk to your backend.
- There is **no background surveillance**: Android does not allow arbitrary
  background monitoring, and Digital Guardian does not pretend otherwise. The
  Settings "Guardian mode" toggle is a user-controlled preference for
  analysis-related notifications/shortcuts, not a covert monitoring service.

### iOS notes

The project is cross-platform (Expo), but unrestricted background scanning is
not possible on iOS either. Use the share sheet, camera, photo library,
notifications manually; deep-link sharing is supported via the `digitalguardian`
scheme.

## 11. Production deployment

```bash
export FLASK_ENV=production
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export DATABASE_URL=postgresql+psycopg://user:pass@host:5432/digital_guardian
export SESSION_COOKIE_SECURE=true

./venv/bin/flask --app wsgi db upgrade
./venv/bin/gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:app
```

Production notes:

- `ProductionConfig.validate()` refuses to boot without a real `SECRET_KEY`.
- Terminate TLS at a reverse proxy (Caddy/nginx) and use HTTPS. HSTS is enabled
  automatically in production.
- Use a real rate-limit store (e.g. `RATELIMIT_STORAGE_URI=redis://…`) when
  running multiple workers.
- For PostgreSQL the app uses `pool_pre_ping`. Install `psycopg` if you use
  `postgresql+psycopg://`.

## 12. Database

- Models: `User`, `UserSettings`, `Scan`.
- `Scan` stores only metadata + the text/URL/QR payload the user explicitly
  submitted; uploaded images are never written to disk or stored as blobs.
- Timestamps are naive-UTC in the DB; every API response serialises them with an
  ISO-8601 `Z` suffix (`models.iso_utc`).
- Migrations live in `migrations/`:
  - `./venv/bin/flask --app wsgi db migrate -m "msg"` (new revision)
  - `./venv/bin/flask --app wsgi db upgrade`
- Retention: `settings.retention_days` (0 = keep); CLI sweep:
  `./venv/bin/flask --app wsgi purge-scans [--days N]`.

## 13. Security & privacy controls

- Password hashing (Werkzeug), CSRF for cookie-authenticated state changes,
  secure cookies, session expiration, login/registration/analysis rate limits,
  user enumeration resistance, ownership checks on all history data.
- Bearer tokens are signed, carry an expiry, and are revocable on logout
  (`token_version`); mobile stores them in `expo-secure-store`.
- Input validation everywhere; upload type/size/dimension limits; safe server
  filenames; no path traversal; XSS mitigated by Jinja autoescaping plus
  `textContent` in JS for untrusted strings.
- Security headers: nosniff, `frame-ancestors 'none'`, Referrer-Policy,
  Permissions-Policy (camera self-only), restrictive CSP.
- SSRF guard for the optional remote URL fetch validates every resolved address
  with the `ipaddress` module (loopback/private/link-local/reserved/metadata
  blocked, re-checked per redirect) with timeouts, size caps and redirect caps.
- No secrets in code; `.env` is git-ignored; no message bodies or tokens logged.
- Analysis output is always advisory — the app never opens links or files
  automatically, never auto-installs content, and never guarantees safety.

## 14. Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError` | Ensure you installed `requirements.txt` (+ `-dev`) into `venv/`. |
| OCR "not available" | Install tesseract at OS level; set `OCR_ENABLED=true`. The app works without it (QR + rules only). |
| Model unavailable on login rows | Rebuild model: `./venv/bin/python ml/train_model.py`. |
| Phone can't reach server | Use the computer's LAN IP, not `localhost`. Check firewall. |
| Analyzed via camera, nothing happens | Browser/camera permission blocked; use upload or manual payload instead. |
| `db upgrade` fails | Fresh DB that predates migrations: use `flask --app app init-db` once. |
| 429 Too many requests | Wait or raise `RATELIMIT_DEFAULT` in `.env`. |

## 15. Known limitations (reported honestly)

- OCR requires the system `tesseract` binary; if absent, image analysis still
  decodes QR codes and explains that OCR was unavailable.
- Server-side QR decode is not enabled (no pyzbar/OpenCV); QR decoding happens
  in the client (web: jsQR, mobile: expo-camera) and analysis on the server.
- Remote URL inspection is off by default by design (`ENABLE_REMOTE_URL_INSPECTION`).
- No real-time threat-intelligence or URL-reputation vendor is configured; no
  such capability is claimed.
- Android share-sheet (`ACTION_SEND`) requires a native build with a share
  module as described in §10; deep links work today.
- No mobile device/emulator toolchain was available in this workspace, so
  mobile behaviour was validated by TypeScript typecheck and an Android JS
  export bundle, not by a physical device.

## 16. License / data provenance

- The SMS Spam Collection dataset originates from the UCI Machine Learning
  Repository (`ml/download_dataset.py` documents the source URL). Consult the
  dataset's documented licensing before redistribution.
- The trained model and dataset are required for local operation and are kept
  in the repository with their regeneration scripts so they can be reproduced.

---

**Digital Guardian — your shield before you click.**