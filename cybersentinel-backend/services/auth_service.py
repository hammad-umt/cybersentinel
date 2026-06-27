"""JWT authentication and user management."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from db.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory revoked token IDs (jti) until expiry — fine for single-server FYP demo.
_revoked_tokens: set[str] = set()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(*, user_id: str, email: str, role: str) -> tuple[str, int]:
    expires_seconds = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": expire,
        "jti": f"{user_id}-{int(expire.timestamp())}",
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, expires_seconds


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti and jti in _revoked_tokens:
            return None
        return payload
    except JWTError:
        return None


def revoke_token(token: str) -> bool:
    payload = decode_access_token(token)
    if not payload:
        return False
    jti = payload.get("jti")
    if jti:
        _revoked_tokens.add(jti)
        return True
    return False


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    normalized = email.strip().lower()
    result = await db.execute(select(User).where(User.email == normalized))
    return result.scalar_one_or_none()


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User | None:
    user = await get_user_by_email(db, email)
    if not user or not verify_password(password, user.password_hash):
        return None
    return user


async def create_user(
    db: AsyncSession,
    email: str,
    password: str,
    role: str = "Analyst",
) -> User:
    normalized = email.strip().lower()
    existing = await get_user_by_email(db, normalized)
    if existing:
        raise ValueError("Email already registered")

    user = User(
        email=normalized,
        password_hash=hash_password(password),
        role=role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def list_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at.asc()))
    return list(result.scalars().all())


async def create_password_reset_token(db: AsyncSession, email: str) -> str | None:
    """Return a one-time reset token for the user, or None if email is unknown."""
    user = await get_user_by_email(db, email)
    if not user:
        return None

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    )
    user.password_reset_token_hash = _hash_reset_token(token)
    user.password_reset_expires = expires_at.isoformat()
    await db.commit()
    return token


async def clear_password_reset_token(db: AsyncSession, email: str) -> None:
    user = await get_user_by_email(db, email)
    if not user:
        return
    user.password_reset_token_hash = None
    user.password_reset_expires = None
    await db.commit()


async def validate_password_reset_token(db: AsyncSession, token: str) -> bool:
    token_hash = _hash_reset_token(token)
    result = await db.execute(select(User).where(User.password_reset_token_hash == token_hash))
    user = result.scalar_one_or_none()
    if not user or not user.password_reset_expires:
        return False

    try:
        expires_at = datetime.fromisoformat(user.password_reset_expires)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return False

    return datetime.now(timezone.utc) <= expires_at


async def reset_password_with_token(db: AsyncSession, token: str, new_password: str) -> bool:
    token_hash = _hash_reset_token(token)
    result = await db.execute(select(User).where(User.password_reset_token_hash == token_hash))
    user = result.scalar_one_or_none()
    if not user or not user.password_reset_expires:
        return False

    try:
        expires_at = datetime.fromisoformat(user.password_reset_expires)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return False

    if datetime.now(timezone.utc) > expires_at:
        return False

    user.password_hash = hash_password(new_password)
    user.password_reset_token_hash = None
    user.password_reset_expires = None
    await db.commit()
    return True


async def ensure_default_admin(db: AsyncSession) -> None:
    """Create the default admin account on first startup if no users exist."""
    count = await db.execute(select(User.id).limit(1))
    if count.scalar_one_or_none() is not None:
        return

    admin_email = settings.default_admin_email
    admin = User(
        email=admin_email,
        password_hash=hash_password(settings.DEFAULT_ADMIN_PASSWORD),
        role="Administrator",
    )
    db.add(admin)
    await db.commit()
    from loguru import logger

    logger.info(
        "Created default admin account '{email}' — change the password after first login",
        email=admin_email,
    )
