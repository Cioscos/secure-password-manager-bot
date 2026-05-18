"""HMAC-based password reuse detector. State is in-memory only."""

from __future__ import annotations

import hashlib
import hmac
from collections import defaultdict


def compute_password_hmac(password: str, hmac_key: bytes) -> str:
    return hmac.new(hmac_key, password.encode("utf-8"), hashlib.sha256).hexdigest()


class ReuseDetector:
    def __init__(self, hmac_key: bytes) -> None:
        self._key = hmac_key
        self._by_hmac: dict[str, dict[str, str]] = defaultdict(dict)
        self._account_to_hmac: dict[str, str] = {}

    def add(self, account_id: str, account_name: str, password: str) -> None:
        self.remove(account_id)
        h = compute_password_hmac(password, self._key)
        self._by_hmac[h][account_id] = account_name
        self._account_to_hmac[account_id] = h

    def add_hmac(self, account_id: str, account_name: str, password_hmac: str) -> None:
        self.remove(account_id)
        self._by_hmac[password_hmac][account_id] = account_name
        self._account_to_hmac[account_id] = password_hmac

    def remove(self, account_id: str) -> None:
        h = self._account_to_hmac.pop(account_id, None)
        if h is None:
            return
        bucket = self._by_hmac.get(h)
        if bucket and account_id in bucket:
            del bucket[account_id]
            if not bucket:
                del self._by_hmac[h]

    def cluster_for(self, password: str) -> list[tuple[str, str]]:
        h = compute_password_hmac(password, self._key)
        return list(self._by_hmac.get(h, {}).items())

    def cluster_for_hmac(self, password_hmac: str) -> list[tuple[str, str]]:
        return list(self._by_hmac.get(password_hmac, {}).items())

    def all_clusters(self, *, min_size: int = 2) -> list[list[tuple[str, str]]]:
        return [
            list(bucket.items()) for bucket in self._by_hmac.values() if len(bucket) >= min_size
        ]
