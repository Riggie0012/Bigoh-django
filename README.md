# Bigoh 

## Django Scaffold (Side-by-Side Test)
This repo includes a minimal Django scaffold for safe testing without touching the Flask app.

Quick test:
1. Install dependencies: `pip install -r requirements.txt`
2. Set DB env vars (same as Flask): `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` (or `DATABASE_URL`)
3. Run: `python manage.py runserver`
4. Visit: `http://127.0.0.1:8000/` (home)
5. DB check: `http://127.0.0.1:8000/health/db`

---

﻿# Bigoh 

Bigoh is a ready-made online store you can run on your computer or deploy online.
This guide is written for beginners. Follow the steps in order and you will have a working store.

## What you get
- Storefront (home, categories, product page)
- Cart and checkout (Pay on Delivery/WhatsApp)
- Admin dashboard (orders, products, flash sales, reviews)
- Reviews + ratings
- Optional email/SMS notifications

## What you need
- A Windows PC (or Mac/Linux)
- Internet connection
- Python 3.10+
- MySQL database (local or hosted)

If you do not know what MySQL is, follow the steps under "Database setup (easy)" below.

---

# 1) Install Python (only once)
1. Go to https://www.python.org/downloads/
2. Download and install Python.
3. During install, tick "Add Python to PATH".

To confirm it worked, open PowerShell and run:
```bash
python --version
```

---

# 2) Download the project
If you already have this folder, skip this step.

---

# 3) Create a virtual environment (recommended)
Open PowerShell in the project folder and run:
```bash
python -m venv .venv
.\.venv\Scripts\activate
```

---

# 4) Install dependencies
```bash
pip install -r requirements.txt
```

---

# 5) Database setup (easy)
You need a MySQL database. There are two options:

## Option A: Use a local MySQL
1. Install MySQL from https://dev.mysql.com/downloads/installer/
2. Create a database (example name: bigoh)
3. Import the schema:
```bash
mysql -u root -p bigoh < scripts/schema.sql
```

## Option B: Use a hosted MySQL (Railway)
1. Create a Railway project.
2. Add a MySQL plugin.
3. Copy the connection string (DATABASE_URL).

---

# 6) Create your .env file
In the project root, create a file called .env.

Start with this minimum:
```
FLASK_SECRET_KEY=your_long_random_key
DATABASE_URL=mysql://user:pass@host:3306/dbname
```

If you use local MySQL instead of DATABASE_URL, use:
```
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=bigoh
```

---

# 7) Run the app
```bash
python app.py
```

Open in your browser:
- Storefront: http://127.0.0.1:5000/
- Admin: http://127.0.0.1:5000/admin

---

# 8) Make yourself admin
Add your username to ADMIN_USERS in .env:
```
ADMIN_USERS=myusername
```

Restart the app after editing .env.

---

# Optional features (only if you want)

## Email notifications
Add SMTP settings in .env:
```
EMAIL_ENABLED=1
EMAIL_FROM=you@example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=you@example.com
SMTP_PASSWORD=yourpassword
SMTP_USE_TLS=1
```

## SMS notifications (Africa's Talking)
```
AFRICASTALKING_USERNAME=your_username
AFRICASTALKING_API_KEY=your_api_key
```

---

# Common problems (simple fixes)
- App won't start: run pip install -r requirements.txt
- Database error: check your DATABASE_URL or DB_* values
- Email not sending: check SMTP details + EMAIL_ENABLED=1

---

# Deploy online (Railway)
1. Push this repo to GitHub.
2. Create a Railway project and connect the repo.
3. Add a MySQL plugin and copy DATABASE_URL.
4. Set env vars in Railway (DATABASE_URL + FLASK_SECRET_KEY).
5. Deploy.

---

# Security tips
- Never share your .env
- Change any leaked passwords immediately


