"""MongoDB storage for opaque MCP sessions and encrypted upstream cookies."""

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pymongo import AsyncMongoClient, ASCENDING
from pymongo.errors import PyMongoError

from .auth_errors import (
    ConfigurationError,
    SessionNotFoundError,
    SessionStoreDataError,
    SessionStoreUnavailableError,
)


@dataclass(frozen=True, repr=False)
class StoredSession:
    cookies: dict[str, str]
    user_id: str
    user_type: str


class MongoSessionStore:
    """Store upstream session cookies encrypted and keyed by an opaque handle."""

    def __init__(
        self,
        uri: str | None,
        database: str,
        collection: str,
        encryption_key: str | None,
    ) -> None:
        if not uri:
            raise ConfigurationError("MONGODB_URI is required.")
        if not encryption_key:
            raise ConfigurationError("AUTH_SESSION_ENCRYPTION_KEY is required.")

        try:
            raw_key = base64.urlsafe_b64decode(
                encryption_key + "=" * (-len(encryption_key) % 4)
            )
        except (ValueError, base64.binascii.Error) as error:
            raise ConfigurationError(
                "AUTH_SESSION_ENCRYPTION_KEY must be a URL-safe base64 encoded 32-byte key."
            ) from error
        if len(raw_key) != 32:
            raise ConfigurationError(
                "AUTH_SESSION_ENCRYPTION_KEY must decode to exactly 32 bytes."
            )

        self._client = AsyncMongoClient(uri)
        self._collection = self._client[database][collection]
        self._cipher = AESGCM(raw_key)

    async def start(self) -> None:
        try:
            await self._client.admin.command("ping")
            await self._collection.create_index(
                [("expires_at", ASCENDING)],
                expireAfterSeconds=0,
            )
        except PyMongoError as error:
            raise SessionStoreUnavailableError(
                "Authentication session storage is unavailable."
            ) from error

    async def close(self) -> None:
        await self._client.close()

    async def create_session(
        self,
        cookies: dict[str, str],
        user_id: str,
        user_type: str,
        ttl_seconds: int,
    ) -> str:
        session_handle = secrets.token_urlsafe(32)
        handle_hash = self._hash_handle(session_handle)
        nonce = secrets.token_bytes(12)
        encrypted_cookies = self._cipher.encrypt(
            nonce,
            json.dumps(
                {
                    "cookies": cookies,
                    "user_id": user_id,
                    "user_type": user_type,
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            handle_hash.encode("ascii"),
        )
        now = datetime.now(timezone.utc)
        document = {
            "_id": handle_hash,
            "encrypted_session": base64.b64encode(encrypted_cookies).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "created_at": now,
            "expires_at": now + timedelta(seconds=ttl_seconds),
        }
        try:
            await self._collection.insert_one(document)
        except PyMongoError as error:
            raise SessionStoreUnavailableError(
                "Authentication session could not be stored."
            ) from error
        return session_handle

    async def get_session(self, session_handle: str) -> StoredSession:
        handle_hash = self._hash_handle(session_handle)
        try:
            document = await self._collection.find_one(
                {
                    "_id": handle_hash,
                    "expires_at": {"$gt": datetime.now(timezone.utc)},
                }
            )
        except PyMongoError as error:
            raise SessionStoreUnavailableError(
                "Authentication session storage is unavailable."
            ) from error
        if document is None:
            raise SessionNotFoundError("The MCP session is missing or expired.")

        try:
            nonce = base64.b64decode(document["nonce"], validate=True)
            encrypted_session = base64.b64decode(
                document["encrypted_session"],
                validate=True,
            )
            session_data: Any = json.loads(
                self._cipher.decrypt(
                    nonce,
                    encrypted_session,
                    handle_hash.encode("ascii"),
                )
            )
            if not isinstance(session_data, dict):
                raise ValueError("Stored session data is malformed.")
            cookie_data = session_data["cookies"]
            user_id = session_data["user_id"]
            user_type = session_data["user_type"]
            if not isinstance(cookie_data, dict) or not all(
                isinstance(name, str) and isinstance(value, str)
                for name, value in cookie_data.items()
            ):
                raise ValueError("Stored cookie data is malformed.")
            if not isinstance(user_id, str) or not isinstance(user_type, str):
                raise ValueError("Stored identity data is malformed.")
        except (InvalidTag, KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
            raise SessionStoreDataError(
                "Stored authentication session data is invalid."
            ) from error

        return StoredSession(
            cookies=cookie_data,
            user_id=user_id,
            user_type=user_type,
        )

    @staticmethod
    def _hash_handle(session_handle: str) -> str:
        return hashlib.sha256(session_handle.encode("utf-8")).hexdigest()
