#!/usr/bin/env python3
"""Async DI check-in/task runner.

The private key is read only into memory. Privy customer/refresh tokens are
persisted in a local SQLite database so an unexpired session can be reused.
Twitter OAuth and browser actions are intentionally out of scope.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import random
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlsplit
from zoneinfo import ZoneInfo

import aiosqlite
from curl_cffi.requests import AsyncSession, RequestsError
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak


DI_BASE = "https://di.xyz"
PRIVY_BASE = "https://auth.privy.io"
PRIVY_APP_ID = "cmsdjnd0n00by0djvu64acvd1"
PRIVY_CLIENT = "react-auth:3.36.1"
CHAIN_ID = 56
CHAIN_CAIP = "eip155:56"
CHECKIN_CONTRACT = "0xC361Eb6E91abD289c912BfCABc644076680659B6"
BSC_RPC = "https://bsc-dataseed.binance.org/"
TASK_KEYS = ("x_follow", "daily_like", "daily_repost")
TASK_LABELS = {
    "x_follow": "关注 X",
    "daily_like": "每日点赞",
    "daily_repost": "每日转发",
}
UTC = timezone.utc
SHANGHAI = ZoneInfo("Asia/Shanghai")
ANSI_GREEN = "\033[32m"
ANSI_RESET = "\033[0m"

# Assigned once when keys.txt is loaded, so labels stay stable for the whole run.
ACCOUNT_LABELS: dict[str, str] = {}


class ApiError(RuntimeError):
    def __init__(self, status: int, code: str, endpoint: str):
        self.status = status
        self.code = code
        self.endpoint = endpoint
        super().__init__(f"{status}:{code}")


class RpcError(RuntimeError):
    pass


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def business_date() -> str:
    return datetime.now(SHANGHAI).date().isoformat()


def account_label(address: str) -> str:
    """Return the stable 1-based label assigned from the unique keys.txt order."""
    return ACCOUNT_LABELS.get(address.lower(), "账号?")


def green(text: str) -> str:
    return f"{ANSI_GREEN}{text}{ANSI_RESET}"



async def sleep_random(low: float, high: float, *, label: str | None = None) -> float:
    """Sleep a short random interval in [low, high]. Returns the chosen delay."""
    if high < low:
        low, high = high, low
    delay = 0.0 if high <= 0 else random.uniform(max(0.0, low), high)
    if delay > 0:
        await asyncio.sleep(delay)
    return delay


def task_label(task_key: str) -> str:
    return TASK_LABELS.get(task_key, task_key)


def parse_daily_time(value: str) -> time:
    match = re.fullmatch(r"([01]\d|2[0-3]):([0-5]\d)", value)
    if not match:
        raise argparse.ArgumentTypeError("每日时间格式应为 HH:MM，例如 00:10")
    return time(hour=int(match.group(1)), minute=int(match.group(2)))


def next_daily_run(daily_at: time) -> datetime:
    now = datetime.now(SHANGHAI)
    scheduled = now.replace(hour=daily_at.hour, minute=daily_at.minute, second=0, microsecond=0)
    if scheduled <= now:
        scheduled += timedelta(days=1)
    return scheduled


def safe_code(value: Any) -> str:
    text = str(value or "unknown")
    text = re.sub(r"[^A-Za-z0-9_.:-]", "_", text)
    return text[:80]


def safe_error(exc: BaseException) -> str:
    if isinstance(exc, ApiError):
        return f"api_{exc.status}_{safe_code(exc.code)}"
    if isinstance(exc, RpcError):
        return f"rpc_{safe_code(str(exc))}"
    return type(exc).__name__


def jwt_exp(token: str | None) -> int | None:
    if not token or token.count(".") != 2:
        return None
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
        value = data.get("exp")
        return int(value) if value is not None else None
    except (ValueError, TypeError, KeyError, binascii.Error, UnicodeError, json.JSONDecodeError):
        return None


def selector(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(path)
    return [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


@dataclass(slots=True)
class ProxySpec:
    url: str = field(repr=False)
    host: str
    port: int

    @property
    def binding_id(self) -> str:
        # Never persist or log the proxy URL, which may contain credentials.
        return hashlib.sha256(self.url.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class AccountSpec:
    private_key: str = field(repr=False)
    address: str
    proxy: ProxySpec | None
    index: int
    profile: "AccountProfile | None" = None


@dataclass(slots=True)
class AccountProfile:
    caid: str
    proxy_binding_id: str | None
    user_agent: str
    accept_language: str


HTTP_PROFILES = (
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "en-US,en;q=0.9"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36", "en-US,en;q=0.9"),
)


def parse_proxy(raw: str) -> ProxySpec:
    value = raw.strip()
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "socks5", "socks5h"}:
            raise ValueError("unsupported proxy scheme")
        if not parsed.hostname or not parsed.port:
            raise ValueError("proxy must include host and port")
        return ProxySpec(value, parsed.hostname, parsed.port)

    parts = value.split(":", 3)
    if len(parts) == 2:
        host, port = parts
        user = password = None
    elif len(parts) == 4:
        host, port, user, password = parts
    else:
        raise ValueError("proxy format must be host:port[:user:password]")
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("invalid proxy host or port")
    if user is None:
        url = f"http://{host}:{port}"
    else:
        url = f"http://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
    return ProxySpec(url, host, int(port))


def load_accounts(
    keys_path: Path,
    proxies_path: Path | None,
    force_direct: bool = False,
) -> list[AccountSpec]:
    keys = read_lines(keys_path)
    result: list[AccountSpec] = []
    seen: set[str] = set()
    for index, raw in enumerate(keys):
        normalized = raw if raw.lower().startswith("0x") else "0x" + raw
        if not re.fullmatch(r"0x[0-9a-fA-F]{64}", normalized):
            raise ValueError(f"invalid private key at line {index + 1}")
        try:
            address = Account.from_key(normalized).address
        except Exception as exc:
            raise ValueError(f"invalid private key at line {index + 1}: {type(exc).__name__}") from None
        lowered = address.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        result.append(AccountSpec(normalized, address, None, index))
    if not result:
        raise ValueError("no usable private key found")
    ACCOUNT_LABELS.clear()
    ACCOUNT_LABELS.update({account.address.lower(): f"账号{number}" for number, account in enumerate(result, start=1)})

    # Proxy rows deliberately remain positional: proxy line N maps to key line N.
    # An empty proxy row means that wallet connects directly. Rows beyond the keys
    # file have no wallet to bind to and are ignored.
    if force_direct or proxies_path is None or not proxies_path.exists():
        return result
    proxy_rows = proxies_path.read_text(encoding="utf-8-sig").splitlines()

    parsed_by_key_index: dict[int, ProxySpec] = {}
    for index, raw_proxy in enumerate(proxy_rows[:len(keys)]):
        raw_proxy = raw_proxy.strip()
        if not raw_proxy:
            continue
        try:
            proxy = parse_proxy(raw_proxy)
        except ValueError as exc:
            raise ValueError(f"invalid proxy line {index + 1}: {safe_code(str(exc))}") from None
        parsed_by_key_index[index] = proxy

    for account in result:
        account.proxy = parsed_by_key_index.get(account.index)
    return result


def browser_headers(profile: AccountProfile) -> dict[str, str]:
    return {
        "User-Agent": profile.user_agent,
        "Accept-Language": profile.accept_language,
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
    }


def privy_headers(profile: AccountProfile, token: str | None = None) -> dict[str, str]:
    headers = {
        "Origin": DI_BASE,
        "Referer": DI_BASE + "/",
        "privy-app-id": PRIVY_APP_ID,
        "privy-client": PRIVY_CLIENT,
        "privy-ca-id": profile.caid,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    headers.update(browser_headers(profile))
    return headers


def di_headers(token: str, profile: AccountProfile) -> dict[str, str]:
    headers = {
        "Origin": DI_BASE,
        "Referer": DI_BASE + "/check-in",
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    headers.update(browser_headers(profile))
    return headers


class HttpTransport:
    def __init__(
        self,
        proxy: ProxySpec | None,
        timeout: float,
        connections: int = 20,
    ):
        self.timeout = timeout
        # curl_cffi impersonates Chrome's TLS, HTTP/2 and browser header profile.
        self.client = AsyncSession(
            max_clients=max(4, connections),
            impersonate="chrome",
            proxy=proxy.url if proxy else None,
        )

    async def close(self) -> None:
        await self.client.close()

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        payload: Any = None,
        params: dict[str, Any] | None = None,
        retries: int = 3,
    ) -> dict[str, Any]:
        attempts = max(1, retries)
        last_error: BaseException | None = None
        for attempt in range(attempts):
            try:
                response = await self.client.request(
                    method,
                    url,
                    headers=headers,
                    json=payload,
                    params=params,
                    timeout=self.timeout,
                )
            except (RequestsError, TimeoutError) as exc:
                last_error = exc
                if attempt + 1 >= attempts:
                    raise
                await asyncio.sleep(min(8.0, 0.6 * (2**attempt)))
                continue

            try:
                body = response.json() if response.content else {}
            except (ValueError, json.JSONDecodeError):
                body = {}
            if 200 <= response.status_code < 300:
                if isinstance(body, dict):
                    return body
                return {"value": body}

            code = body.get("code") or body.get("error") if isinstance(body, dict) else None
            error = ApiError(response.status_code, safe_code(code or f"http_{response.status_code}"), urlsplit(url).path)
            if response.status_code not in {408, 425, 429} and response.status_code < 500:
                raise error
            last_error = error
            if attempt + 1 >= attempts:
                raise error
            retry_after = response.headers.get("retry-after")
            try:
                delay = float(retry_after) if retry_after else 0.6 * (2**attempt)
            except ValueError:
                delay = 0.6 * (2**attempt)
            await asyncio.sleep(min(10.0, max(0.2, delay)))
        if last_error:
            raise last_error
        raise RuntimeError("request failed")


@dataclass(slots=True)
class TokenBundle:
    token: str | None = None
    refresh_token: str | None = None
    privy_access_token: str | None = None
    identity_token: str | None = None
    token_exp: int | None = None
    user_id: str | None = None

    def active(self, safety_seconds: int = 60) -> bool:
        if not self.token:
            return False
        if self.token_exp is None:
            return True
        return self.token_exp > int(now_utc().timestamp()) + safety_seconds


class CredentialStore:
    def __init__(self, path: Path):
        self.path = path
        self.db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = await aiosqlite.connect(self.path)
        self.db.row_factory = aiosqlite.Row
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS credentials (
                address TEXT PRIMARY KEY,
                token TEXT,
                refresh_token TEXT,
                privy_access_token TEXT,
                identity_token TEXT,
                token_exp INTEGER,
                user_id TEXT,
                updated_at TEXT NOT NULL
            )"""
        )
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS task_runs (
                address TEXT NOT NULL,
                task_key TEXT NOT NULL,
                period_key TEXT NOT NULL,
                content_revision_id INTEGER,
                status TEXT NOT NULL,
                detail TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(address, task_key, period_key, content_revision_id)
            )"""
        )
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS checkins (
                address TEXT PRIMARY KEY,
                tx_hash TEXT,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS account_profiles (
                address TEXT PRIMARY KEY,
                caid TEXT NOT NULL,
                proxy_binding_id TEXT,
                user_agent TEXT NOT NULL,
                accept_language TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        # Older databases used a UNIQUE proxy binding. Positional proxy rows may
        # intentionally reuse a proxy, so rebuild only that small profile table.
        indexes = await self.db.execute("PRAGMA index_list(account_profiles)")
        index_rows = await indexes.fetchall()
        await indexes.close()
        has_unique_proxy_index = False
        for index_row in index_rows:
            if not index_row[2]:
                continue
            index_name = str(index_row[1]).replace('"', '""')
            columns = await self.db.execute(f'PRAGMA index_info("{index_name}")')
            column_rows = await columns.fetchall()
            await columns.close()
            if [str(column_row[2]) for column_row in column_rows] == ["proxy_binding_id"]:
                has_unique_proxy_index = True
                break
        if has_unique_proxy_index:
            await self.db.execute("ALTER TABLE account_profiles RENAME TO account_profiles_legacy")
            await self.db.execute(
                """CREATE TABLE account_profiles (
                    address TEXT PRIMARY KEY,
                    caid TEXT NOT NULL,
                    proxy_binding_id TEXT,
                    user_agent TEXT NOT NULL,
                    accept_language TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            await self.db.execute(
                """INSERT INTO account_profiles
                   (address, caid, proxy_binding_id, user_agent, accept_language, created_at, updated_at)
                   SELECT address, caid, proxy_binding_id, user_agent, accept_language, created_at, updated_at
                   FROM account_profiles_legacy"""
            )
            await self.db.execute("DROP TABLE account_profiles_legacy")
        await self.db.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    async def close(self) -> None:
        if self.db is not None:
            await self.db.close()

    async def load_or_create_profiles(
        self,
        accounts: list[AccountSpec],
        rebind_proxies: bool = False,
    ) -> None:
        """Persist stable HTTP profiles and the current positional proxy assignment."""
        assert self.db is not None

        rows: dict[str, aiosqlite.Row] = {}
        for account in accounts:
            cursor = await self.db.execute(
                "SELECT caid, proxy_binding_id, user_agent, accept_language "
                "FROM account_profiles WHERE address = ?",
                (account.address.lower(),),
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is not None:
                rows[account.address.lower()] = row

        async def create_profile(account: AccountSpec, binding_id: str | None) -> AccountProfile:
            digest = hashlib.sha256(account.address.lower().encode("ascii")).digest()[0]
            user_agent, accept_language = HTTP_PROFILES[digest % len(HTTP_PROFILES)]
            profile = AccountProfile(str(uuid.uuid4()), binding_id, user_agent, accept_language)
            timestamp = iso_z(now_utc())
            await self.db.execute(
                """INSERT INTO account_profiles
                   (address, caid, proxy_binding_id, user_agent, accept_language, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (account.address.lower(), profile.caid, binding_id, profile.user_agent,
                 profile.accept_language, timestamp, timestamp),
            )
            return profile

        def profile_from_row(row: aiosqlite.Row, binding_id: str | None) -> AccountProfile:
            return AccountProfile(
                str(row["caid"]),
                binding_id,
                str(row["user_agent"]),
                str(row["accept_language"]),
            )

        # proxy.txt is positional and authoritative: a blank row makes that same
        # numbered wallet direct; a nonblank row binds only to that wallet.
        timestamp = iso_z(now_utc())
        for account in accounts:
            address = account.address.lower()
            row = rows.get(address)
            binding_id = account.proxy.binding_id if account.proxy is not None else None
            if row is None:
                account.profile = await create_profile(account, binding_id)
                continue
            if row["proxy_binding_id"] != binding_id:
                await self.db.execute(
                    "UPDATE account_profiles SET proxy_binding_id = ?, updated_at = ? WHERE address = ?",
                    (binding_id, timestamp, address),
                )
            account.profile = profile_from_row(row, binding_id)
        await self.db.commit()

    async def get_credentials(self, address: str) -> TokenBundle:
        assert self.db is not None
        cursor = await self.db.execute(
            "SELECT token, refresh_token, privy_access_token, identity_token, token_exp, user_id "
            "FROM credentials WHERE address = ?",
            (address.lower(),),
        )
        row = await cursor.fetchone()
        await cursor.close()
        if row is None:
            return TokenBundle()
        return TokenBundle(
            token=row[0],
            refresh_token=row[1],
            privy_access_token=row[2],
            identity_token=row[3],
            token_exp=row[4],
            user_id=row[5],
        )

    async def save_credentials(self, address: str, bundle: TokenBundle) -> None:
        assert self.db is not None
        await self.db.execute(
            """INSERT INTO credentials
               (address, token, refresh_token, privy_access_token, identity_token,
                token_exp, user_id, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(address) DO UPDATE SET
                 token=excluded.token,
                 refresh_token=excluded.refresh_token,
                 privy_access_token=excluded.privy_access_token,
                 identity_token=excluded.identity_token,
                 token_exp=excluded.token_exp,
                 user_id=excluded.user_id,
                 updated_at=excluded.updated_at""",
            (
                address.lower(),
                bundle.token,
                bundle.refresh_token,
                bundle.privy_access_token,
                bundle.identity_token,
                bundle.token_exp,
                bundle.user_id,
                iso_z(now_utc()),
            ),
        )
        await self.db.commit()

    async def save_task(
        self,
        address: str,
        task_key: str,
        period_key: str,
        content_revision_id: int | None,
        status: str,
        detail: str = "",
    ) -> None:
        assert self.db is not None
        await self.db.execute(
            """INSERT INTO task_runs
               (address, task_key, period_key, content_revision_id, status, detail, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(address, task_key, period_key, content_revision_id) DO UPDATE SET
                 status=excluded.status, detail=excluded.detail, updated_at=excluded.updated_at""",
            (
                address.lower(),
                task_key,
                period_key,
                content_revision_id,
                status,
                detail[:200],
                iso_z(now_utc()),
            ),
        )
        await self.db.commit()

    async def save_checkin(self, address: str, tx_hash: str | None, status: str) -> None:
        assert self.db is not None
        await self.db.execute(
            """INSERT INTO checkins(address, tx_hash, status, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(address) DO UPDATE SET
                 tx_hash=excluded.tx_hash, status=excluded.status, updated_at=excluded.updated_at""",
            (address.lower(), tx_hash, status, iso_z(now_utc())),
        )
        await self.db.commit()


class AuthManager:
    def __init__(
        self,
        account: AccountSpec,
        transport: HttpTransport,
        store: CredentialStore,
        logger: logging.Logger,
    ):
        self.account = account
        self.transport = transport
        self.store = store
        self.logger = logger
        if account.profile is None:
            raise RuntimeError("account profile was not initialized")
        self.profile = account.profile
        self.bundle = TokenBundle()
        self.lock = asyncio.Lock()

    def _merge_tokens(self, response: dict[str, Any], previous: TokenBundle | None = None) -> TokenBundle:
        old = previous or self.bundle
        token = response.get("token") or old.token
        refresh = response.get("refresh_token") or old.refresh_token
        pat = response.get("privy_access_token") or old.privy_access_token
        identity = response.get("identity_token") or old.identity_token
        user = response.get("user") if isinstance(response.get("user"), dict) else {}
        user_id = user.get("id") or old.user_id
        return TokenBundle(
            token=token,
            refresh_token=refresh,
            privy_access_token=pat,
            identity_token=identity,
            token_exp=jwt_exp(token),
            user_id=user_id,
        )

    async def _sync_identity(self, token: str) -> None:
        response = await self.transport.request_json(
            "POST",
            DI_BASE + "/api/identity/sync",
            headers=di_headers(token, self.profile),
            payload={},
        )
        user = response.get("user") if isinstance(response.get("user"), dict) else {}
        if user.get("id"):
            self.bundle.user_id = str(user["id"])
        await self.store.save_credentials(self.account.address, self.bundle)

    async def _login(self) -> str:
        address = self.account.address
        headers = privy_headers(self.profile)
        nonce_response = await self.transport.request_json(
            "POST",
            PRIVY_BASE + "/api/v1/siwe/init",
            headers=headers,
            payload={"address": address},
        )
        nonce = nonce_response.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise RuntimeError("Privy did not return a SIWE nonce")
        message = (
            f"di.xyz wants you to sign in with your Ethereum account:\n{address}\n\n"
            "By signing, you are proving you own this wallet and logging in. "
            "This does not initiate a transaction or cost any fees.\n\n"
            f"URI: {DI_BASE}\nVersion: 1\nChain ID: 56\nNonce: {nonce}\n"
            f"Issued At: {iso_z(now_utc())}\nResources:\n- https://privy.io"
        )
        signature = Account.sign_message(
            encode_defunct(text=message), self.account.private_key
        ).signature.hex()
        if not signature.startswith("0x"):
            signature = "0x" + signature
        response = await self.transport.request_json(
            "POST",
            PRIVY_BASE + "/api/v1/siwe/authenticate",
            headers=headers,
            payload={
                "signature": signature,
                "message": message,
                "chainId": CHAIN_CAIP,
                "walletClientType": None,
                "connectorType": None,
                "mode": "login-or-sign-up",
            },
        )
        self.bundle = self._merge_tokens(response)
        if not self.bundle.token:
            raise RuntimeError("Privy login returned no customer token")
        await self.store.save_credentials(address, self.bundle)
        await self._sync_identity(self.bundle.token)
        self.logger.info("[%s] Privy 登录完成", account_label(address))
        return self.bundle.token

    async def _refresh(self, previous: TokenBundle) -> str:
        if not previous.refresh_token:
            raise RuntimeError("no refresh token")
        response = await self.transport.request_json(
            "POST",
            PRIVY_BASE + "/api/v1/sessions",
            headers=privy_headers(self.profile, previous.token),
            payload={"refresh_token": previous.refresh_token},
        )
        if response.get("session_update_action") == "clear":
            raise RuntimeError("Privy session was cleared")
        self.bundle = self._merge_tokens(response, previous)
        if not self.bundle.token:
            raise RuntimeError("Privy refresh returned no customer token")
        await self.store.save_credentials(self.account.address, self.bundle)
        try:
            await self._sync_identity(self.bundle.token)
        except ApiError as exc:
            if exc.status == 401:
                raise RuntimeError("refreshed token rejected by DI") from None
            raise
        self.logger.info("[%s] 已复用刷新后的 Privy 凭据", account_label(self.account.address))
        return self.bundle.token

    async def ensure(self, force: bool = False) -> str:
        async with self.lock:
            stored = await self.store.get_credentials(self.account.address)
            if not force and stored.active():
                self.bundle = stored
                if self.bundle.user_id:
                    return self.bundle.token  # type: ignore[return-value]
                try:
                    await self._sync_identity(self.bundle.token)  # type: ignore[arg-type]
                    return self.bundle.token  # type: ignore[return-value]
                except ApiError as exc:
                    if exc.status != 401:
                        raise
            if stored.refresh_token:
                try:
                    self.bundle = stored
                    return await self._refresh(stored)
                except (ApiError, RequestsError, RuntimeError):
                    self.logger.info("[%s] 缓存凭据已失效，重新进行 SIWE 签名", account_label(self.account.address))
            self.bundle = TokenBundle()
            return await self._login()

    async def recover(self) -> str:
        return await self.ensure(force=True)


class DIClient:
    def __init__(self, transport: HttpTransport, auth: AuthManager):
        self.transport = transport
        self.auth = auth

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: Any = None,
        params: dict[str, Any] | None = None,
        retry_auth: bool = True,
    ) -> dict[str, Any]:
        token = await self.auth.ensure()
        try:
            return await self.transport.request_json(
                method,
                DI_BASE + path,
                headers=di_headers(token, self.auth.profile),
                payload=payload,
                params=params,
            )
        except ApiError as exc:
            if exc.status != 401 or not retry_auth:
                raise
            token = await self.auth.recover()
            return await self.transport.request_json(
                method,
                DI_BASE + path,
                headers=di_headers(token, self.auth.profile),
                payload=payload,
                params=params,
            )

    async def engagement(self, address: str) -> dict[str, Any]:
        response = await self.request(
            "GET",
            "/api/engagement/me",
            params={"walletAddress": address},
        )
        engagement = response.get("engagement")
        if not isinstance(engagement, dict):
            raise RuntimeError("DI engagement response is missing engagement")
        return engagement

    async def start_task(self, task_key: str, content_revision_id: int | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"taskKey": task_key}
        if content_revision_id is not None:
            body["contentRevisionId"] = content_revision_id
        response = await self.request("POST", "/api/tasks/verification/start", payload=body)
        task = response.get("task")
        if not isinstance(task, dict):
            raise RuntimeError("DI task start response is missing task")
        return task

    async def complete_task(self, task_key: str, content_revision_id: int | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"taskKey": task_key}
        if content_revision_id is not None:
            body["contentRevisionId"] = content_revision_id
        response = await self.request("POST", "/api/tasks/verification/complete", payload=body)
        task = response.get("task")
        if not isinstance(task, dict):
            raise RuntimeError("DI task completion response is missing task")
        return task

    async def create_attempt(self, address: str) -> dict[str, Any]:
        response = await self.request(
            "POST",
            "/api/check-in/attempts",
            payload={"chainId": CHAIN_ID, "walletAddress": address.lower()},
        )
        attempt = response.get("attempt")
        if not isinstance(attempt, dict):
            raise RuntimeError("DI check-in attempt response is missing attempt")
        return attempt

    async def patch_attempt(self, action: str, **fields: Any) -> dict[str, Any]:
        response = await self.request(
            "PATCH",
            "/api/check-in/attempts",
            payload={"action": action, **fields},
        )
        return response.get("attempt", response)

    async def confirm_checkin(self, attempt_id: str, tx_hash: str) -> dict[str, Any]:
        response = await self.request(
            "POST",
            "/api/check-in/confirm",
            payload={"attemptId": attempt_id, "txHash": tx_hash},
        )
        return response.get("checkIn", response)


class BscRpc:
    def __init__(self, transport: HttpTransport, url: str):
        self.transport = transport
        self.url = url
        self.request_id = 0

    async def call(self, method: str, params: list[Any], read_only: bool = True) -> Any:
        self.request_id += 1
        response = await self.transport.request_json(
            "POST",
            self.url,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            payload={"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params},
            retries=3 if read_only else 2,
        )
        if response.get("error"):
            error = response["error"]
            if isinstance(error, dict):
                raise RpcError(safe_code(error.get("code")) + "_" + safe_code(error.get("message")))
            raise RpcError(safe_code(error))
        if "result" not in response:
            raise RpcError("missing_result")
        return response["result"]

    async def can_check_in_today(self, address: str) -> bool:
        data = selector("canCheckInToday(address)") + address[2:].lower().rjust(64, "0")
        result = await self.call("eth_call", [{"to": CHECKIN_CONTRACT, "data": data}, "latest"])
        if not isinstance(result, str):
            raise RpcError("invalid_bool_result")
        return int(result, 16) != 0

    async def check_in(
        self,
        account: AccountSpec,
        *,
        gas_multiplier: float = 1.15,
    ) -> str:
        address = account.address
        data = selector("checkIn()")
        call = {"from": address, "to": CHECKIN_CONTRACT, "data": data}
        gas_hex, gas_price_hex, nonce_hex = await asyncio.gather(
            self.call("eth_estimateGas", [call]),
            self.call("eth_gasPrice", []),
            self.call("eth_getTransactionCount", [address, "pending"]),
        )
        gas = max(21_000, int(gas_hex, 16))
        gas = int(gas * gas_multiplier) + 1
        transaction = {
            "chainId": CHAIN_ID,
            "nonce": int(nonce_hex, 16),
            "to": CHECKIN_CONTRACT,
            "data": data,
            "value": 0,
            "gas": gas,
            "gasPrice": int(gas_price_hex, 16),
        }
        signed = Account.sign_transaction(transaction, account.private_key)
        raw = signed.raw_transaction.hex()
        if not raw.startswith("0x"):
            raw = "0x" + raw
        tx_hash = await self.call("eth_sendRawTransaction", [raw], read_only=False)
        if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
            raise RpcError("invalid_transaction_hash")
        return tx_hash

    async def wait_receipt(self, tx_hash: str, timeout_seconds: float = 150.0) -> dict[str, Any]:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            receipt = await self.call("eth_getTransactionReceipt", [tx_hash])
            if isinstance(receipt, dict):
                return receipt
            await asyncio.sleep(2.0)
        raise RpcError("receipt_timeout")


def task_period_and_revision(
    engagement: dict[str, Any], task_key: str
) -> tuple[str, int | None] | None:
    if task_key == "x_follow":
        return "once", None
    content = engagement.get("daily_x_content")
    if not isinstance(content, dict) or content.get("content_revision_id") is None:
        return None
    return business_date(), int(content["content_revision_id"])


def matching_task(
    engagement: dict[str, Any], task_key: str, period_key: str, revision: int | None
) -> dict[str, Any] | None:
    tasks = engagement.get("tasks")
    if not isinstance(tasks, list):
        return None
    for task in tasks:
        if not isinstance(task, dict) or task.get("task_key") != task_key:
            continue
        if task.get("period_key") != period_key:
            continue
        if task_key != "x_follow" and task.get("content_revision_id") != revision:
            continue
        return task
    return None


async def complete_after_ready(
    di: DIClient,
    store: CredentialStore,
    address: str,
    task_key: str,
    period_key: str,
    revision: int | None,
    task: dict[str, Any],
    logger: logging.Logger,
    dry_run: bool,
) -> bool:
    available = parse_iso(task.get("verification_available_at"))
    if available:
        delay = (available - now_utc()).total_seconds() + 0.1
        if delay > 0:
            await asyncio.sleep(min(60.0, delay))
    if dry_run:
        logger.info("[%s] 演练模式：将完成任务 %s", account_label(address), task_label(task_key))
        return True

    for attempt in range(6):
        try:
            result = await di.complete_task(task_key, revision)
            status = str(result.get("status", "completed"))
            await store.save_task(address, task_key, period_key, revision, status, "complete")
            if status == "completed" or result.get("awarded") is True:
                logger.info("[%s] 任务 %s 已完成", account_label(address), task_label(task_key))
                return True
            logger.warning("[%s] 任务 %s 返回状态：%s", account_label(address), task_label(task_key), status)
            return False
        except ApiError as exc:
            if exc.code in {"TASK_NOT_READY", "VERIFICATION_NOT_READY", "CHECKIN_CONFIRMATIONS_PENDING"}:
                await asyncio.sleep(1.0 + attempt * 0.5)
                continue
            if exc.code in {"TASK_ALREADY_COMPLETED", "ALREADY_COMPLETED"}:
                await store.save_task(address, task_key, period_key, revision, "completed", exc.code)
                return True
            await store.save_task(address, task_key, period_key, revision, "error", safe_code(exc.code))
            logger.warning("[%s] 完成任务 %s 失败：%s", account_label(address), task_label(task_key), safe_error(exc))
            return False
    logger.warning("[%s] 任务 %s 多次重试后仍未就绪", account_label(address), task_label(task_key))
    return False


async def run_protocol_tasks(
    di: DIClient,
    store: CredentialStore,
    address: str,
    requested: Iterable[str],
    logger: logging.Logger,
    dry_run: bool,
) -> None:
    engagement = await di.engagement(address)
    pending: list[tuple[str, str, int | None, dict[str, Any]]] = []
    for task_key in requested:
        period_revision = task_period_and_revision(engagement, task_key)
        if period_revision is None:
            logger.info("[%s] 跳过 %s：今日 X 内容暂不可用", account_label(address), task_label(task_key))
            continue
        period_key, revision = period_revision
        current = matching_task(engagement, task_key, period_key, revision)
        if current and current.get("status") == "completed":
            logger.info("[%s] %s 已完成，跳过", account_label(address), task_label(task_key))
            continue
        if current and current.get("status") == "verifying":
            task = current
        elif dry_run:
            logger.info("[%s] 演练模式：将开始任务 %s", account_label(address), task_label(task_key))
            continue
        else:
            try:
                task = await di.start_task(task_key, revision)
                await store.save_task(address, task_key, str(task.get("period_key", period_key)), revision, str(task.get("status", "verifying")), "start")
                logger.info("[%s] 已开始协议任务 %s", account_label(address), task_label(task_key))
            except ApiError as exc:
                if exc.code in {"TASK_ALREADY_COMPLETED", "ALREADY_COMPLETED"}:
                    logger.info("[%s] %s 在启动时已完成，跳过", account_label(address), task_label(task_key))
                    continue
                logger.warning("[%s] 启动任务 %s 失败：%s", account_label(address), task_label(task_key), safe_error(exc))
                await store.save_task(address, task_key, period_key, revision, "error", safe_code(exc.code))
                continue
        pending.append((task_key, period_key, revision, task))

    if pending:
        await asyncio.gather(
            *(
                complete_after_ready(di, store, address, key, period, revision, task, logger, dry_run)
                for key, period, revision, task in pending
            )
        )
        final = await di.engagement(address)
        logger.info("[%s] 当前积分：%s", account_label(address), final.get("points_balance", "?"))


async def run_checkin(
    di: DIClient,
    rpc: BscRpc,
    store: CredentialStore,
    account: AccountSpec,
    logger: logging.Logger,
    dry_run: bool,
) -> None:
    address = account.address
    can_checkin = await rpc.can_check_in_today(address)
    if not can_checkin:
        await store.save_checkin(address, None, "already_checked_in")
        logger.info("[%s] %s", account_label(address), green("今日链上签到已完成"))
        return
    if dry_run:
        logger.info("[%s] 演练模式：将提交链上签到", account_label(address))
        return

    attempt = await di.create_attempt(address)
    attempt_id = attempt.get("id")
    if not isinstance(attempt_id, str) or not attempt_id:
        raise RuntimeError("DI check-in attempt is missing an id")
    tx_hash: str | None = None
    try:
        tx_hash = await rpc.check_in(account)
        await store.save_checkin(address, tx_hash, "broadcasted")
        await di.patch_attempt("submitted", attemptId=attempt_id, txHash=tx_hash)
        logger.info("[%s] 签到交易已提交：%s", account_label(address), tx_hash)
        receipt = await rpc.wait_receipt(tx_hash)
        if receipt.get("status") not in {"0x1", 1}:
            raise RpcError("transaction_reverted")
        for retry in range(6):
            try:
                result = await di.confirm_checkin(attempt_id, tx_hash)
                await store.save_checkin(address, tx_hash, str(result.get("status", "completed")))
                logger.info("[%s] 签到已确认", account_label(address))
                return
            except ApiError as exc:
                if exc.code not in {"CHECKIN_RECEIPT_NOT_READY", "CHECKIN_CONFIRMATIONS_PENDING"}:
                    raise
                await asyncio.sleep(2.0 + retry * 0.25)
        raise RuntimeError("DI check-in confirmation did not complete in time")
    except Exception:
        if tx_hash is None:
            await di.patch_attempt("failed", attemptId=attempt_id, failureCode="SUBMISSION_FAILED")
            await store.save_checkin(address, None, "submission_failed")
        raise


async def run_account(
    account: AccountSpec,
    store: CredentialStore,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> None:
    transport = HttpTransport(account.proxy, args.timeout)
    try:
        auth = AuthManager(account, transport, store, logger)
        di = DIClient(transport, auth)
        rpc = BscRpc(transport, args.rpc_url)
        await auth.ensure()
        engagement = await di.engagement(account.address)
        logger.info(
            "[%s] 会话已就绪；积分=%s；已跟踪任务=%s",
            account_label(account.address),
            engagement.get("points_balance", "?"),
            len(engagement.get("tasks") or []),
        )
        operations: list[Any] = []
        if not args.no_checkin:
            operations.append(run_checkin(di, rpc, store, account, logger, args.dry_run))
        if not args.no_tasks:
            operations.append(run_protocol_tasks(di, store, account.address, TASK_KEYS, logger, args.dry_run))
        if operations:
            # A single wallet serializes check-in and task writes to reduce rate and nonce races.
            for operation_index, operation in enumerate(operations):
                await operation
                if operation_index + 1 < len(operations):
                    delay = await sleep_random(
                        args.operation_delay_min, args.operation_delay_max
                    )
                    if delay > 0:
                        logger.debug(
                            "[%s] 操作间隔 %.2fs",
                            account_label(account.address),
                            delay,
                        )
    finally:
        await transport.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DI 钱包登录、链上签到与协议任务执行器。"
    )
    parser.add_argument("--keys", type=Path, default=Path("keys.txt"), help="每行一个 EVM 私钥")
    parser.add_argument(
        "--proxies",
        type=Path,
        default=Path("proxy.txt"),
        help="可选代理文件；每钱包一行，文件为空或不存在时自动直连",
    )
    parser.add_argument("--state", type=Path, default=Path("di_state.sqlite3"), help="本地凭据与档案缓存")
    parser.add_argument("--concurrency", type=int, default=1, help="最大钱包并发数（默认：1）")
    parser.add_argument("--timeout", type=float, default=30.0, help="单次请求超时秒数")
    parser.add_argument("--rpc-url", default=BSC_RPC, help="BSC JSON-RPC 节点地址")
    parser.add_argument(
        "--direct",
        action="store_true",
        help="强制直连并忽略 proxy.txt",
    )
    parser.add_argument(
        "--rebind-proxies",
        action="store_true",
        help="用当前 proxy.txt 替换已保存的钱包-代理绑定",
    )
    parser.add_argument(
        "--operation-delay",
        type=float,
        default=None,
        help="兼容旧参数：设为同一钱包操作间隔的下限，上限为其 +1.5 秒",
    )
    parser.add_argument(
        "--operation-delay-min",
        type=float,
        default=1.0,
        help="同一钱包签到与任务之间的随机间隔下限秒数（默认：1.0）",
    )
    parser.add_argument(
        "--operation-delay-max",
        type=float,
        default=3.0,
        help="同一钱包签到与任务之间的随机间隔上限秒数（默认：3.0）",
    )
    parser.add_argument(
        "--account-delay-min",
        type=float,
        default=0.5,
        help="不同钱包启动前的随机错开下限秒数（默认：0.5）",
    )
    parser.add_argument(
        "--account-delay-max",
        type=float,
        default=2.5,
        help="不同钱包启动前的随机错开上限秒数（默认：2.5）",
    )
    parser.add_argument(
        "--schedule-jitter-seconds",
        type=float,
        default=30.0,
        help="每日/循环下次执行时间的短随机抖动上限秒数（默认：30）",
    )
    loop_mode = parser.add_mutually_exclusive_group()
    loop_mode.add_argument(
        "--daily-loop",
        dest="loop_mode",
        action="store_const",
        const="daily",
        help="持续运行：执行全部流程，之后每天按北京时间定时执行",
    )
    loop_mode.add_argument(
        "--checkin-loop",
        dest="loop_mode",
        action="store_const",
        const="checkin",
        help="持续运行：只执行链上签到，按固定间隔循环（默认）",
    )
    loop_mode.add_argument(
        "--once",
        dest="loop_mode",
        action="store_const",
        const="once",
        help="仅执行一轮后退出",
    )
    parser.set_defaults(loop_mode="checkin")
    parser.add_argument(
        "--daily-at",
        type=parse_daily_time,
        default=time(0, 10),
        metavar="HH:MM",
        help="每日循环的北京时间执行时间（默认：00:10）",
    )
    parser.add_argument(
        "--daily-retry-minutes",
        type=float,
        default=15.0,
        help="每日循环遇到运行失败后的重试间隔分钟数（默认：15）",
    )
    parser.add_argument(
        "--checkin-interval-hours",
        type=float,
        default=24.0,
        help="仅签到循环的间隔小时数（默认：24）",
    )
    parser.add_argument("--dry-run", action="store_true", help="只登录和读取状态，不提交写操作")
    parser.add_argument("--no-checkin", action="store_true", help="跳过链上签到")
    parser.add_argument("--no-tasks", action="store_true", help="跳过协议任务验证")
    parser.add_argument("--verbose", action="store_true", help="启用调试日志（不会记录敏感凭据）")
    args = parser.parse_args()
    args.daily_loop = args.loop_mode == "daily"
    args.checkin_loop = args.loop_mode == "checkin"
    if args.concurrency < 1:
        parser.error("--concurrency 必须至少为 1")
    if args.timeout <= 0:
        parser.error("--timeout 必须大于 0")
    if args.operation_delay is not None:
        if args.operation_delay < 0:
            parser.error("--operation-delay 不能为负数")
        args.operation_delay_min = args.operation_delay
        args.operation_delay_max = args.operation_delay + 1.5
    for name, value in (
        ("--operation-delay-min", args.operation_delay_min),
        ("--operation-delay-max", args.operation_delay_max),
        ("--account-delay-min", args.account_delay_min),
        ("--account-delay-max", args.account_delay_max),
        ("--schedule-jitter-seconds", args.schedule_jitter_seconds),
    ):
        if value < 0:
            parser.error(f"{name} 不能为负数")
    if args.operation_delay_max < args.operation_delay_min:
        parser.error("--operation-delay-max 不能小于 --operation-delay-min")
    if args.account_delay_max < args.account_delay_min:
        parser.error("--account-delay-max 不能小于 --account-delay-min")
    if args.daily_retry_minutes <= 0:
        parser.error("--daily-retry-minutes 必须大于 0")
    if args.checkin_interval_hours <= 0:
        parser.error("--checkin-interval-hours 必须大于 0")
    if args.checkin_loop:
        if args.no_checkin:
            parser.error("--checkin-loop 不能与 --no-checkin 同时使用")
        args.no_tasks = True
    if args.no_checkin and args.no_tasks:
        parser.error("签到和任务不能同时跳过")
    return args


async def run_once(args: argparse.Namespace, logger: logging.Logger) -> int:
    try:
        accounts = load_accounts(args.keys, args.proxies, args.direct)
    except (OSError, ValueError) as exc:
        logger.error("输入错误：%s", safe_code(str(exc)))
        return 2
    network_mode = "直连" if all(account.proxy is None for account in accounts) else "一钱包一代理"
    logger.info(
        "已加载 %d 个唯一钱包；并发=%d；演练模式=%s；网络=%s；操作间隔=%.1f~%.1fs；账号错开=%.1f~%.1fs",
        len(accounts),
        args.concurrency,
        args.dry_run,
        network_mode,
        args.operation_delay_min,
        args.operation_delay_max,
        args.account_delay_min,
        args.account_delay_max,
    )
    store = CredentialStore(args.state)
    try:
        await store.open()
        await store.load_or_create_profiles(accounts, args.rebind_proxies)
    except (OSError, aiosqlite.Error, ValueError) as exc:
        await store.close()
        logger.error("账户档案错误：%s", safe_code(str(exc)))
        return 2
    semaphore = asyncio.Semaphore(args.concurrency)
    failures: list[tuple[str, str]] = []

    async def guarded(account: AccountSpec) -> None:
        stagger = await sleep_random(args.account_delay_min, args.account_delay_max)
        if stagger > 0:
            logger.debug("[%s] 启动错开 %.2fs", account_label(account.address), stagger)
        async with semaphore:
            try:
                await run_account(account, store, args, logger)
            except Exception as exc:
                failures.append((account_label(account.address), safe_error(exc)))
                logger.error("[%s] 执行失败：%s", account_label(account.address), safe_error(exc))

    try:
        await asyncio.gather(*(guarded(account) for account in accounts))
    finally:
        await store.close()
    if failures:
        logger.error("执行结束：%d 个钱包失败：%s", len(failures), ", ".join(f"{a}={e}" for a, e in failures))
        return 1
    logger.info("本轮执行成功")
    return 0


async def async_main(args: argparse.Namespace) -> int:
    for level, label in (
        (logging.DEBUG, "调试"),
        (logging.INFO, "信息"),
        (logging.WARNING, "警告"),
        (logging.ERROR, "错误"),
        (logging.CRITICAL, "严重错误"),
    ):
        logging.addLevelName(level, label)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("curl_cffi").setLevel(logging.WARNING)
    logger = logging.getLogger("di")
    if not args.daily_loop and not args.checkin_loop:
        return await run_once(args, logger)

    if args.checkin_loop:
        logger.info(
            "已启用仅链上签到循环：先检查当前状态，之后每 %s 小时执行；按 Ctrl+C 停止。",
            f"{args.checkin_interval_hours:g}",
        )
    else:
        logger.info(
            "已启用每日循环：先执行当前轮，之后每天北京时间 %s 执行；按 Ctrl+C 停止。",
            args.daily_at.strftime("%H:%M"),
        )
    while True:
        result = await run_once(args, logger)
        if result == 2:
            logger.error("配置错误，已停止循环。")
            return result
        if result == 0:
            if args.checkin_loop:
                next_run = datetime.now(SHANGHAI) + timedelta(hours=args.checkin_interval_hours)
                logger.info(
                    "本轮链上签到处理完成；下次执行时间（北京时间）：%s",
                    next_run.strftime("%Y-%m-%d %H:%M:%S"),
                )
            else:
                next_run = next_daily_run(args.daily_at)
                logger.info("本轮完成；下次执行时间（北京时间）：%s", next_run.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            next_run = datetime.now(SHANGHAI) + timedelta(minutes=args.daily_retry_minutes)
            logger.warning(
                "本轮失败；将在北京时间 %s 重试。",
                next_run.strftime("%Y-%m-%d %H:%M:%S"),
            )
        wait_seconds = max(0.1, (next_run - datetime.now(SHANGHAI)).total_seconds())
        # Short schedule jitter so recurring runs are not perfectly synchronized.
        wait_seconds += random.uniform(0.0, args.schedule_jitter_seconds)
        await asyncio.sleep(wait_seconds)


def main() -> int:
    try:
        return asyncio.run(async_main(parse_args()))
    except KeyboardInterrupt:
        logging.getLogger("di").info("已停止。")
        return 130


if __name__ == "__main__":
    sys.exit(main())
