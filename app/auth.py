import hashlib
from itsdangerous import URLSafeSerializer
from app.config import SECRET_KEY

serializer = URLSafeSerializer(SECRET_KEY)


def hash_password(password: str) -> str:
    # VULNERABILITY: Unsalted MD5 hashing
    return hashlib.md5(password.encode()).hexdigest()


def create_session_token(user_id: int, username: str, role: str) -> str:
    # VULNERABILITY: Session fixation by accepting externally supplied session cookie elsewhere
    return serializer.dumps({"user_id": user_id, "username": username, "role": role})


def parse_session_token(token: str):
    try:
        return serializer.loads(token)
    except Exception:
        return None


def predictable_reset_token(username: str) -> str:
    # VULNERABILITY: Predictable token generation
    return f"reset-{username}-12345"
