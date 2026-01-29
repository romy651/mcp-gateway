"""
Persistent per-user token storage for Atlassian OAuth refresh tokens.

Stores tokens in Redis with Fernet encryption at rest. Refresh tokens are
long-lived and must persist across gateway restarts.

Requires:
  - REDIS_URL env var (default: redis://localhost:6379/0)
  - TOKEN_ENCRYPTION_KEY env var (Fernet key, required)

Generate a key with:
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

import redis
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("obo-gateway.token_store")

DEFAULT_LEGACY_PATH = os.path.join(os.path.dirname(__file__), ".tokens.json")
KEY_PREFIX = "atlassian_tokens:"


class TokenStore:
    """Redis-backed per-user token storage with encryption at rest."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
        encryption_key: Optional[str] = None,
    ):
        self._redis_url = redis_url or os.environ.get(
            "REDIS_URL", "redis://localhost:6379/0"
        )
        encryption_key_str = encryption_key or os.environ.get(
            "TOKEN_ENCRYPTION_KEY", ""
        )

        if not encryption_key_str:
            raise ValueError(
                "TOKEN_ENCRYPTION_KEY is required. "
                'Generate with: python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )

        try:
            self._cipher = Fernet(encryption_key_str.encode())
        except Exception as e:
            raise ValueError(f"Invalid TOKEN_ENCRYPTION_KEY: {e}")

        try:
            self._redis = redis.from_url(
                self._redis_url,
                decode_responses=False,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            self._redis.ping()
            logger.info("Connected to Redis at %s", self._redis_url)
        except Exception as e:
            raise ValueError(f"Failed to connect to Redis at {self._redis_url}: {e}")

        self._migrate_from_file()

    def _make_key(self, email: str) -> str:
        return f"{KEY_PREFIX}{email.lower()}"

    def _encrypt(self, tokens: dict) -> bytes:
        return self._cipher.encrypt(json.dumps(tokens).encode())

    def _decrypt(self, encrypted_data: bytes) -> Optional[dict]:
        try:
            return json.loads(self._cipher.decrypt(encrypted_data).decode())
        except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error("Failed to decrypt token data: %s", e)
            return None

    def get(self, email: str) -> Optional[dict]:
        """Get stored tokens for a user. Returns None if not found."""
        key = self._make_key(email)
        encrypted_data = self._redis.get(key)
        if not encrypted_data:
            return None

        tokens = self._decrypt(encrypted_data)
        if tokens:
            logger.debug("Token found for %s", email)
        else:
            logger.warning("Corrupted token data for %s, deleting", email)
            self._redis.delete(key)
        return tokens

    def put(self, email: str, tokens: dict):
        """
        Store tokens for a user.

        Args:
            email: User's email address (used as key).
            tokens: Dict with 'access_token', 'refresh_token', 'expires_at',
                    'cloud_id', 'scope', 'site_url', etc.
        """
        key = self._make_key(email)
        self._redis.set(key, self._encrypt(tokens))
        logger.info("Stored tokens for %s", email)

    def remove(self, email: str):
        """Remove stored tokens for a user."""
        key = self._make_key(email)
        deleted = self._redis.delete(key)
        if deleted:
            logger.info("Removed tokens for %s", email)

    def has_user(self, email: str) -> bool:
        """Check if a user has stored tokens."""
        return bool(self._redis.exists(self._make_key(email)))

    def list_users(self) -> list[str]:
        """List all users with stored tokens."""
        keys = []
        cursor = 0
        while True:
            cursor, batch = self._redis.scan(
                cursor, match=f"{KEY_PREFIX}*", count=100
            )
            keys.extend(batch)
            if cursor == 0:
                break

        return sorted(
            key.decode().removeprefix(KEY_PREFIX) for key in keys
        )

    def _migrate_from_file(self):
        """Migrate tokens from legacy .tokens.json to Redis (one-time)."""
        legacy_path = Path(DEFAULT_LEGACY_PATH)
        if not legacy_path.exists():
            return

        try:
            with open(legacy_path, "r") as f:
                legacy_data = json.load(f)

            migrated = 0
            for email, tokens in legacy_data.items():
                if not self.has_user(email):
                    self.put(email, tokens)
                    migrated += 1

            legacy_path.rename(legacy_path.with_suffix(".json.migrated"))
            logger.info(
                "Migrated %d users from %s to Redis", migrated, legacy_path
            )
        except Exception as e:
            logger.error("Migration from legacy file failed: %s", e)
