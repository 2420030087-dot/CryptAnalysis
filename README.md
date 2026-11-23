# 🛡️ FileShield — Real-Time File Integrity Monitoring & AI Anomaly Detection

**FileShield** is an advanced host-based file integrity monitoring (FIM) and behavioral AI anomaly detection cybersecurity system. It continuously guards sensitive organizational assets, validates cryptographic fingerprints using **SHA-256**, applies deterministic security rules, and leverages a **local AI behavioral anomaly engine** to detect, score, and remediate unauthorized modifications in real time.

---

## 🚀 Key Features & Capabilities

- **100% Zero-Cost Local Operation**: Runs completely locally on your machine with ₹0 cost, requiring no paid cloud APIs or external data storage.
- **📥 Native Drag & Drop File Protection**:
  - Drag and drop any file directly onto the **Protected Assets** dashboard panel to immediately baseline and protect it.
  - Interactive **"+ Add Files"** modal with native OS file and directory picker buttons (`Choose Files`, `Choose Folder`).
  - Automatic baseline SHA-256 calculation and pristine snapshot generation for every added file.
- **📁 Directory Path Management & 1-Click Untrack**:
  - Dedicated **"Manage Paths"** control modal showing all actively monitored folders with active file count badges.
  - Remove an entire folder tree from monitoring with 1 click without harming physical files on disk.
- **🔍 Quick Search & Status Filtering**:
  - Live search bar by file name, path, or extension across hundreds of monitored assets.
  - Filter by status (**All**, **Violations Only**, **Deleted Only**, **Safe Only**) or by monitored directory.
  - Interactive KPI cards: Clicking **Deleted Files** or **Modified Files** instantly isolates those files in the table.
- **🔐 Operator Authentication & Multi-User Support**:
  - Role-based session management with cryptographic salted password hashing (`SHA-256` + unique salt).
  - Quick 1-Click Demo Login (`admin` / `admin123`) and support for Google Identity / OAuth.
- **📧 Automated Email Security Alerts**:
  - Real-time alert emails dispatched whenever a monitored file is tampered, altered, or deleted.
  - Alerts are automatically delivered to the email address used during login or registration.
  - Integrated **Live Mail Outbox** on the dashboard to inspect and preview all dispatched alerts in real time, with optional live SMTP delivery (Gmail/Outlook).
- **🚨 Brute-Force Intrusion Detection**:
  - Automatically intercepts consecutive invalid login attempts (>3 failed attempts).
  - Dispatches an emergency intrusion warning email to the registered administrator.
  - Emits a high-severity `FAILED_LOGIN_BURST` security incident to the live SOC feed.
- **🔑 Forgot Password & OTP Recovery**:
  - Self-service password recovery using 6-digit One-Time Passwords (OTP) delivered to the operator's email.
- **🔍 "What Changed?" Visual Code Diff Inspector**:
  - Side-by-side and unified line diffing comparing baseline snapshots to altered files (green for additions, red for deletions).
- **🔄 Instant 1-Click Byte-Exact Restoration**:
  - Reverts tampered or deleted files on disk back to their original pristine state in milliseconds.
- **⚡ Built-In Attack Simulation Lab**:
  - 1-click simulations: `Tamper SQL`, `Ransomware Burst Attack`, `Unauthorized File Deletion`, `Routine Maintenance`, and `Restore All`.

---

## 🏛️ System Architecture

```text
               👤 SECURITY ANALYST / OPERATOR
                             │
                             ▼
                 ┌────────────────────────┐
                 │  FILESHIELD DASHBOARD  │
                 │   (Web UI & WebSockets)│
                 └───────────┬────────────┘
                             │  WebSocket / REST APIs
                             ▼
                 ┌────────────────────────┐
                 │    FASTAPI BACKEND     │
                 └───────────┬────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
    SQLite               AI ENGINE           EMAIL SERVICE
(Database Store)     (Burst & Anomaly XAI) (Alert Dispatcher)
       ▲                     │                     │
       │                     ▼                     ▼
       │                Risk Scores           Mail Outbox
       │                  (0-100)           (HTML Templates)
       │
       └────────────── Security Events 
                             ▲
                             │
                 ┌───────────┴────────────┐
                 │    WATCHDOG AGENT      │
                 │                        │
                 │ Real-Time OS Events    │
                 │ SHA-256 Hasher Engine  │
                 │ Byte Snapshot Manager  │
                 └───────────┬────────────┘
                             │
                             ▼
                   PROTECTED DIRECTORIES
             (./protected_files, custom folders)
```

---

## 🛠️ Component Breakdown

| Component | Responsibility | What Question It Answers |
| :--- | :--- | :--- |
| **Authentication Engine** | Operator login, registration, Google auth, and session security | *Who is authorized to inspect system telemetry?* |
| **Intrusion Shield** | Failed login tracking (>3 attempts) & brute-force mitigation | *Is someone trying to compromise credentials?* |
| **Password Recovery** | Forgot password flow with 6-digit OTP verification | *How do authorized operators regain access safely?* |
| **Watchdog File Agent** | Continuous kernel-level OS file system watcher | *What happened on disk and when?* |
| **SHA-256 Engine** | Cryptographic digest calculation for files | *Did file contents change by even a single byte?* |
| **Diff Engine** | Unified line-by-line comparison against snapshots | *What exact lines or payload got injected?* |
| **Restore Engine** | Deterministic rollback from pristine byte snapshots | *How do we recover instantly from a compromise?* |
| **Rules Engine** | Deterministic severity assignment matrix | *How critical is this incident?* |
| **AI Behavioral Engine**| Temporal event velocity & burst pattern analysis | *Does this activity match ransomware or human error?* |
| **Email Dispatcher** | Live notification router with HTML alert outbox | *How do we alert security leads off-console?* |
| **SOC Dashboard** | Clean dark-mode SIEM console with real-time stream | *What should the security analyst triage right now?* |

---

## ⚡ Quick Start

### 1. Requirements
- Python 3.9+
- Modern Web Browser (Chrome, Edge, Firefox, Brave)

### 2. Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/your-username/fileshield.git
cd fileshield
pip install -r requirements.txt
```

### 3. Launch the Server
Run the startup script or execute directly with Python:

```bash
python main.py
```

The system will start and serve the dashboard at:
👉 **`http://127.0.0.1:8000`**

### 4. Default Credentials
- **Username**: `admin`
- **Password**: `admin123`
- Or click **"⚡ Quick 1-Click Login"** on the gateway screen.

---

## 🎯 Step-by-Step Demo Guide for Faculty & Evaluators

### 1. Drag & Drop File Protection
1. Open the dashboard at `http://127.0.0.1:8000`.
2. Drag any file from your computer and drop it directly onto the **Protected Assets** panel (or click **"+ Add Files"**).
3. The file is saved to disk, assigned a SHA-256 cryptographic baseline, snapshotted, and added to active real-time monitoring.

### 2. Live Tampering & Automated Email Alert
1. In the Attack Simulation Center, click **"Tamper SQL"**.
2. FileShield intercepts the change within milliseconds:
   - Status switches to **`VIOLATION`**.
   - Severity is calculated as **`CRITICAL`**.
   - Risk score is computed by the AI anomaly engine.
3. Click **"Outbox"** in the top navigation:
   - View the dispatched alert email addressed to your active account email.
   - Click **"Preview"** to examine the HTML security report containing old hash, new hash, and threat details.

### 3. Visual "What Changed?" Diff & 1-Click Restore
1. In the Protected Assets table, click **"🔍 What Changed?"** next to `database.sql`.
2. Review the line-by-line diff with unauthorized injected lines highlighted in green.
3. Click **"🔄 Restore"** to restore pristine baseline bytes back to disk. The file status immediately returns to **`SAFE`**.

### 4. Ransomware Burst Simulation
1. Click **"Ransomware Burst"** in the simulation strip.
2. Multiple files are modified within a 1-second interval.
3. The AI Behavioral Engine detects the rapid temporal velocity, flags an **AI Anomaly**, and tags the incident with high threat velocity.

### 5. Brute-Force Intrusion Defense
1. Click **"Logout"** in the top navbar.
2. Enter an incorrect password 4 times on the login screen.
3. On the 4th attempt, FileShield:
   - Blocks the burst with an intrusion banner.
   - Dispatches a brute-force alert email to the admin.
   - Records a `FAILED_LOGIN_BURST` incident in the SOC log.

### 6. Directory Path Management
1. Click **"📁 Manage Paths"** on the Protected Assets toolbar.
2. Inspect all monitored directory roots with file counts.
3. Click **"🗑️ Remove Path"** to untrack an entire directory and clear its files from FileShield in a single click.

---

## 📁 Project Structure

```text
crypt/
├── backend/
│   ├── agent.py            # Watchdog filesystem observer
│   ├── ai_engine.py        # Temporal anomaly & burst scoring
│   ├── app.py              # FastAPI REST endpoints & WebSocket server
│   ├── database.py         # SQLite connection & schema management
│   ├── diff_engine.py      # Unified diff generator & snapshot rollback
│   ├── email_service.py    # Email notification dispatcher & HTML templates
│   ├── integrity.py        # SHA-256 hashing & metadata utilities
│   ├── rules_engine.py     # Deterministic severity matrix
│   └── simulator.py        # Cyber attack simulation logic
├── protected_files/        # Monitored directory containing protected files
├── snapshots/              # Pristine byte-exact snapshots for rollback
├── static/
│   ├── css/
│   │   └── style.css       # Clean cyber-SOC dark mode styling
│   ├── js/
│   │   └── app.js          # Live frontend controller & WebSocket client
│   └── index.html          # Unified SIEM/SOC dashboard interface
├── main.py                 # Application bootstrap entrypoint
├── requirements.txt        # Python package dependencies
└── README.md               # Documentation & project manual
```

---

## ⚖️ License
This project is open-source under the MIT License.
