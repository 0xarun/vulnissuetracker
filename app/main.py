import json
import os
import pickle
import shlex
import subprocess
from datetime import datetime

import requests
from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.auth import hash_password, create_session_token, parse_session_token, predictable_reset_token
from app.config import DEBUG
from app.database import get_db, init_db
from app.logging_config import access_logger, error_logger, sql_logger

app = FastAPI(debug=DEBUG)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# VULNERABILITY: CORS allow all
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()


def current_user(request: Request):
    token = request.cookies.get("session")
    if not token:
        return None
    return parse_session_token(token)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    msg = f'{request.client.host} - - [{datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{request.method} {request.url.path} HTTP/1.1" {response.status_code} {response.headers.get("content-length", "0")} "{request.headers.get("user-agent", "-")}"'
    access_logger.info(msg)
    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request, "user": current_user(request)})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
def register(username: str = Form(...), email: str = Form(...), password: str = Form(...), role: str = Form("user")):
    conn = get_db()
    try:
        # VULNERABILITY: Mass assignment role during registration
        conn.execute(f"INSERT INTO users(username,email,password,role) VALUES('{username}','{email}','{hash_password(password)}','{role}')")
        conn.commit()
    except Exception as e:
        sql_logger.info(f"SQL ERROR register: {e}")
        return PlainTextResponse(str(e), status_code=500)
    return RedirectResponse("/login", 302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    # VULNERABILITY: SQL injection in login
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
    try:
        user = conn.execute(query).fetchone()
    except Exception as e:
        sql_logger.info(f"SQL ERROR login: {e}")
        return PlainTextResponse(str(e), status_code=500)
    if not user:
        return PlainTextResponse("Invalid credentials", status_code=401)
    session_token = create_session_token(user["id"], user["username"], user["role"])
    response = RedirectResponse("/issues", 302)
    # VULNERABILITY: Session fixation (does not rotate if existing passed)
    response.set_cookie("session", request.cookies.get("session", session_token), httponly=False)
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse("/", 302)
    response.delete_cookie("session")
    return response


@app.get("/issues", response_class=HTMLResponse)
def list_issues(request: Request, q: str = ""):
    conn = get_db()
    # VULNERABILITY: SQL injection in search
    sql = f"SELECT issues.*, users.username FROM issues LEFT JOIN users ON issues.owner_id=users.id WHERE title LIKE '%{q}%' OR description LIKE '%{q}%' ORDER BY id DESC"
    try:
        issues = conn.execute(sql).fetchall()
    except Exception as e:
        sql_logger.info(f"SQL ERROR search: {e}")
        issues = []
    return templates.TemplateResponse("issues.html", {"request": request, "issues": issues, "user": current_user(request), "q": q})


@app.get("/issues/new", response_class=HTMLResponse)
def new_issue_page(request: Request):
    return templates.TemplateResponse("create_issue.html", {"request": request, "user": current_user(request)})


@app.post("/issues/new")
def create_issue(request: Request, title: str = Form(...), description: str = Form(...), status: str = Form("open")):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    conn = get_db()
    conn.execute(
        "INSERT INTO issues(title,description,status,owner_id,created_at) VALUES(?,?,?,?,?)",
        (title, description, status, user["user_id"], datetime.utcnow().isoformat()),
    )
    conn.commit()
    return RedirectResponse("/issues", 302)


@app.get("/issues/{issue_id}", response_class=HTMLResponse)
def issue_detail(issue_id: int, request: Request):
    conn = get_db()
    issue = conn.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
    comments = conn.execute("SELECT comments.*, users.username FROM comments LEFT JOIN users ON users.id=comments.user_id WHERE issue_id=?", (issue_id,)).fetchall()
    return templates.TemplateResponse("issue_detail.html", {"request": request, "issue": issue, "comments": comments, "user": current_user(request)})


@app.post("/issues/{issue_id}/edit")
def edit_issue(issue_id: int, title: str = Form(...), description: str = Form(...), status: str = Form(...)):
    conn = get_db()
    # VULNERABILITY: IDOR edit without ownership or role checks
    conn.execute("UPDATE issues SET title=?, description=?, status=? WHERE id=?", (title, description, status, issue_id))
    conn.commit()
    return RedirectResponse(f"/issues/{issue_id}", 302)


@app.post("/issues/{issue_id}/delete")
def delete_issue(issue_id: int):
    conn = get_db()
    # VULNERABILITY: Broken access control delete without auth
    conn.execute("DELETE FROM issues WHERE id=?", (issue_id,))
    conn.commit()
    return RedirectResponse("/issues", 302)


@app.post("/issues/{issue_id}/comment")
def add_comment(request: Request, issue_id: int, content: str = Form(...)):
    user = current_user(request)
    uid = user["user_id"] if user else 1
    conn = get_db()
    # VULNERABILITY: Stored XSS via unescaped comment rendering
    conn.execute("INSERT INTO comments(issue_id,user_id,content,created_at) VALUES(?,?,?,?)", (issue_id, uid, content, datetime.utcnow().isoformat()))
    conn.commit()
    return RedirectResponse(f"/issues/{issue_id}", 302)


@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request, "user": current_user(request)})


@app.post("/upload")
def upload_file(request: Request, issue_id: int = Form(...), file: UploadFile = File(...)):
    # VULNERABILITY: Insecure file upload no extension/content validation
    os.makedirs("uploads", exist_ok=True)
    path = f"uploads/{file.filename}"
    with open(path, "wb") as f:
        f.write(file.file.read())
    access_logger.info(f"UPLOAD by {request.client.host}: {path}")
    conn = get_db()
    conn.execute("UPDATE issues SET attachment=? WHERE id=?", (file.filename, issue_id))
    conn.commit()
    return RedirectResponse(f"/issues/{issue_id}", 302)


@app.get("/download")
def download(name: str):
    # VULNERABILITY: Directory traversal & direct object reference
    return FileResponse(f"uploads/{name}")


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    conn = get_db()
    # VULNERABILITY: Missing role validation for admin page
    users = conn.execute("SELECT * FROM users").fetchall()
    issues = conn.execute("SELECT * FROM issues").fetchall()
    return templates.TemplateResponse("admin.html", {"request": request, "users": users, "issues": issues, "user": current_user(request)})


@app.get("/activity", response_class=HTMLResponse)
def activity(request: Request):
    conn = get_db()
    rows = conn.execute("SELECT * FROM activity_logs ORDER BY id DESC").fetchall()
    return templates.TemplateResponse("activity.html", {"request": request, "logs": rows, "user": current_user(request)})


@app.get("/api/issues")
def api_issues():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM issues").fetchall()]
    return rows


@app.post("/api/issues")
def api_create_issue(payload: dict):
    conn = get_db()
    # VULNERABILITY: Mass assignment from JSON body
    conn.execute(
        f"INSERT INTO issues(title,description,status,owner_id,created_at) VALUES('{payload.get('title')}','{payload.get('description')}','{payload.get('status','open')}',{payload.get('owner_id',1)},'{datetime.utcnow().isoformat()}')"
    )
    conn.commit()
    return {"ok": True}


@app.get("/api/user/{user_id}")
def api_user(user_id: int):
    conn = get_db()
    # VULNERABILITY: IDOR user data exposure
    row = conn.execute("SELECT id,username,email,role FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else {}


@app.get("/fetch")
def fetch_url(url: str):
    # VULNERABILITY: SSRF with no URL/IP validation
    access_logger.info(f"SSRF fetch attempted: {url}")
    data = requests.get(url, timeout=4)
    return PlainTextResponse(data.text[:2000])


@app.get("/cmd")
def run_cmd(cmd: str):
    # VULNERABILITY: Command injection
    output = subprocess.getoutput(cmd)
    return {"output": output}


@app.post("/deserialize")
def deserialize(data: str = Form(...)):
    # VULNERABILITY: Unsafe deserialization
    obj = pickle.loads(bytes.fromhex(data))
    return {"result": str(obj)}


@app.get("/render")
def render_name(name: str):
    # VULNERABILITY: SSTI-like unsafe template rendering from input
    from jinja2 import Template
    return HTMLResponse(Template(name).render())


@app.get("/redirect")
def open_redirect(next: str):
    # VULNERABILITY: Open redirect
    return RedirectResponse(next)


@app.get("/reset")
def reset_password(username: str):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        # VULNERABILITY: User enumeration
        return {"error": "user not found"}
    token = predictable_reset_token(username)
    conn.execute("UPDATE users SET reset_token=? WHERE username=?", (token, username))
    conn.commit()
    return {"reset_token": token}


@app.get("/superadmin")
def superadmin():
    return {"message": "Hidden superadmin endpoint", "debug": True}


@app.get("/backup.sql")
def backup_exposed():
    return PlainTextResponse("-- backup\nSELECT * FROM users;\nadmin,0192023a7bbd73250516f069df18b500")


@app.get("/robots.txt")
def robots():
    return FileResponse("app/static/robots.txt")


@app.get("/health")
def health():
    return JSONResponse({"status": "ok", "debug": DEBUG})


@app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception):
    # VULNERABILITY: Detailed error leakage
    error_logger.info(f"{datetime.utcnow().isoformat()} ERROR {exc}")
    return PlainTextResponse(f"Internal error: {repr(exc)}", status_code=500)
