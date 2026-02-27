# VULNERABILITY: Hardcoded secrets / insecure defaults
SECRET_KEY = "supersecret"
DEBUG = True
ALLOWED_HOSTS = ["*"]
JWT_SECRET = "weakjwtsecret"
DATABASE_PATH = "vulnissue.db"
ADMIN_DEFAULT_USER = "admin"
ADMIN_DEFAULT_PASSWORD = "admin123"
