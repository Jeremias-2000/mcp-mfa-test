import base64
import secrets
import unittest
from datetime import datetime, timezone
from typing import Any

from pymongo.errors import PyMongoError

from test_mcp_2.auth_errors import (
    ConfigurationError,
    SessionNotFoundError,
    SessionStoreDataError,
    SessionStoreUnavailableError,
)
from test_mcp_2.session_manager import MongoSessionStore


class MemoryCollection:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}

    async def insert_one(self, document: dict[str, Any]) -> None:
        self.documents[document["_id"]] = document

    async def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
        document = self.documents.get(query["_id"])
        if document is None:
            return None
        expiry = query["expires_at"]["$gt"]
        if document["expires_at"] <= expiry:
            return None
        return document


class MongoSessionStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        self.store = MongoSessionStore(
            uri="mongodb://127.0.0.1:27017",
            database="test",
            collection="sessions",
            encryption_key=key,
        )
        self.collection = MemoryCollection()
        self.store._collection = self.collection

    async def asyncTearDown(self) -> None:
        await self.store.close()

    async def test_stores_only_encrypted_cookies_and_returns_session(self) -> None:
        upstream_cookies = {
            "csrf_token": "csrf-value",
            "session_id": "upstream-session-value",
        }
        handle = await self.store.create_session(
            cookies=upstream_cookies,
            user_id="user-123",
            user_type="regular",
            ttl_seconds=600,
        )

        document = next(iter(self.collection.documents.values()))
        self.assertNotIn(handle, document["_id"])
        self.assertNotIn("upstream-session-value", str(document))
        self.assertNotIn("csrf-value", str(document))
        self.assertNotIn("user-123", str(document))

        restored = await self.store.get_session(handle)
        self.assertEqual(restored.cookies, upstream_cookies)
        self.assertEqual(restored.user_id, "user-123")
        self.assertEqual(restored.user_type, "regular")

    async def test_missing_session_is_rejected(self) -> None:
        with self.assertRaises(SessionNotFoundError):
            await self.store.get_session("unknown-handle")

    async def test_tampered_cookie_ciphertext_is_rejected(self) -> None:
        handle = await self.store.create_session(
            cookies={"session_id": "upstream-session-value"},
            user_id="user-123",
            user_type="regular",
            ttl_seconds=600,
        )
        document = next(iter(self.collection.documents.values()))
        document["encrypted_session"] = base64.b64encode(b"tampered").decode("ascii")

        with self.assertRaises(SessionStoreDataError):
            await self.store.get_session(handle)

    async def test_expired_session_is_rejected(self) -> None:
        handle = await self.store.create_session(
            cookies={"session_id": "upstream-session-value"},
            user_id="user-123",
            user_type="regular",
            ttl_seconds=600,
        )
        document = next(iter(self.collection.documents.values()))
        document["expires_at"] = datetime(2000, 1, 1, tzinfo=timezone.utc)

        with self.assertRaises(SessionNotFoundError):
            await self.store.get_session(handle)

    async def test_configuration_requires_uri_and_valid_encryption_key(self) -> None:
        with self.assertRaises(ConfigurationError):
            MongoSessionStore(
                uri=None,
                database="test",
                collection="sessions",
                encryption_key="valid-placeholder",
            )
        with self.assertRaises(ConfigurationError):
            MongoSessionStore(
                uri="mongodb://127.0.0.1:27017",
                database="test",
                collection="sessions",
                encryption_key=None,
            )
        with self.assertRaises(ConfigurationError):
            MongoSessionStore(
                uri="mongodb://127.0.0.1:27017",
                database="test",
                collection="sessions",
                encryption_key="not-a-32-byte-key",
            )

    async def test_database_failures_are_mapped_to_store_unavailable(self) -> None:
        class FailingCollection:
            async def insert_one(self, _document: dict[str, Any]) -> None:
                raise PyMongoError("insert failed")

            async def find_one(self, _query: dict[str, Any]) -> None:
                raise PyMongoError("find failed")

        self.store._collection = FailingCollection()
        with self.assertRaises(SessionStoreUnavailableError):
            await self.store.create_session(
                cookies={"session_id": "secret"},
                user_id="user-1",
                user_type="regular",
                ttl_seconds=60,
            )
        with self.assertRaises(SessionStoreUnavailableError):
            await self.store.get_session("some-handle")

    async def test_start_pings_database_and_creates_expiry_index(self) -> None:
        class FakeAdmin:
            async def command(self, command: str) -> None:
                self.command_name = command

        class FakeClient:
            def __init__(self) -> None:
                self.admin = FakeAdmin()

        class IndexedCollection:
            async def create_index(
                self,
                keys: list[tuple[str, int]],
                **options: Any,
            ) -> None:
                self.keys = keys
                self.options = options

        original_client = self.store._client
        client = FakeClient()
        collection = IndexedCollection()
        self.store._client = client
        self.store._collection = collection
        try:
            await self.store.start()
        finally:
            self.store._client = original_client

        self.assertEqual(client.admin.command_name, "ping")
        self.assertEqual(collection.keys, [("expires_at", 1)])
        self.assertEqual(collection.options, {"expireAfterSeconds": 0})

    async def test_start_maps_database_failures(self) -> None:
        class FailingAdmin:
            async def command(self, _command: str) -> None:
                raise PyMongoError("ping failed")

        class FakeClient:
            admin = FailingAdmin()

        original_client = self.store._client
        self.store._client = FakeClient()
        try:
            with self.assertRaises(SessionStoreUnavailableError):
                await self.store.start()
        finally:
            self.store._client = original_client


if __name__ == "__main__":
    unittest.main()
