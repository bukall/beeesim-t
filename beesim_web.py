"""BeeSIM Web 2.3.6 HTTP API, including its public client signing scheme.

Signing constants below come from the public Web bundle, not a user account.
User tokens are kept only in this object; no credentials or logs are persisted.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

WEB_VERSION = "2.3.6"
FIRMWARE_KEY = "BEESIM_FW_UPGRADE_NONE"
PATHS = {
    "rsp": "/v2/plugin/esim/rsp/es9plus/execute.do",
    "firmware": "/v2/plugin/mall/firmware.do",
    "login": "/v1/main/user/mall/login.do",
    "bluetooth": "/v1/main/user/mall/jwt/bluetooth.do",
    "vercode": "/v1/main/common/mall/vercode.do",
    "user": "/v1/main/user/mall.do",
    "logger": "/v1/main/common/logger.do",
}


def _client_secret(kind):
    override = os.environ.get("BEESIM_" + kind.upper() + "_SIGNING_SECRET")
    if override:
        return override
    # Public Web protocol constants, retained encrypted in the same form as JS.
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    encrypted = {"BeeSIM": "wIGnQfM3wcSvr6iROzD4yCrsZ+4tvNewXoQuezs08CY=",
                 "Mall": "W4Vj8VJr4l3u8foMr+Llmft+OYhYSjMJM+JEXa5Qb24="}[kind]
    decryptor = Cipher(algorithms.AES(b"22f313619b7d6b80"), modes.CBC(b"fc8124a9d2cb6eb4")).decryptor()
    padded = decryptor.update(base64.b64decode(encrypted)) + decryptor.finalize()
    unpad = PKCS7(128).unpadder()
    return (unpad.update(padded) + unpad.finalize()).decode()


# functionExecutionStatus values that count as success. Executed-WithWarning is
# a valid SGP.22 success-with-warning state; the official handleReasonCode only
# rejects when the envelope status != 200 (reasonCode selects the message).
_OK_STATUSES = (None, "Executed-Success", "Executed-WithWarning")


def _execution_status(data: dict, action: str) -> dict:
    """Return data.header.functionExecutionStatus.

    Tolerate a missing/None header or status (treated as success, as the Web
    does), but reject a *present but malformed* header/status instead of
    silently treating a corrupt ES9+ response as success (fail-closed).
    """
    header = data.get("header")
    if header is None:
        return {}
    if not isinstance(header, dict):
        raise RuntimeError(f"ES9+ {action}: malformed response header")
    status = header.get("functionExecutionStatus")
    if status is None:
        return {}
    if not isinstance(status, dict):
        raise RuntimeError(f"ES9+ {action}: malformed functionExecutionStatus")
    return status


def _require_ok(status: dict, action: str) -> None:
    """Raise unless the functionExecutionStatus is a success state."""
    if status.get("status") not in _OK_STATUSES:
        raise RuntimeError(f"ES9+ {action}: {status.get('status')}")


class WebAPI:
    def __init__(self, base_url="https://beeesim.com", *, token=None, timeout=40,
                 opener=None, clock=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen
        self._clock = clock or time.time

    def _request(self, family, action, payload):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        query = "action=" + action
        headers = {"Content-Type": "application/json;charset=UTF-8", "Accept": "application/json"}
        if family in ("firmware", "login", "bluetooth", "vercode", "user"):
            mall = family == "firmware"
            timestamp = str(int(self._clock() * 1000))
            token = self.token if family == "bluetooth" else ""
            if family == "bluetooth" and not token:
                raise ValueError("Login required for account device management")
            signing = query + body + (token or "") + timestamp + _client_secret("Mall" if mall else "BeeSIM")
            prefix = "X" if mall else "B"
            headers[prefix + "-Timestamp"] = timestamp
            headers[prefix + "-Sign"] = hashlib.md5(base64.b64encode(signing.encode())).hexdigest()
            if token:
                headers["B-Token"] = token
        url = self.base_url + "/fetch" + PATHS[family] + "?" + urllib.parse.urlencode({"action": action})
        request = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
        try:
            with self._opener(request, timeout=self.timeout) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"BeeSIM {family}/{action}: HTTP {exc.code}") from exc
        if not isinstance(result, dict):
            raise RuntimeError("Invalid BeeSIM API response")
        if result.get("status") != 200:
            if result.get("status") == 401:
                self.token = None
            # Do not echo server messages that may contain account/activation data.
            raise RuntimeError(f"BeeSIM {family}/{action}: status {result.get('status')} (request failed)")
        return result

    async def request(self, family, action, payload):
        if family not in PATHS:
            raise ValueError("Unknown API family")
        return await asyncio.to_thread(self._request, family, action, payload)

    async def execute(self, action, smdp, protocol, fields):
        if action not in ("initiateAuthentication", "authenticateClient", "getBoundProfilePackage", "handleNotification"):
            raise ValueError("Unknown ES9+ action")
        payload = dict(fields, smdpAddress=smdp, protocol=protocol)
        result = await self.request("rsp", action, payload)
        data = result.get("data")
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise RuntimeError(f"ES9+ {action}: unexpected response data")
        _require_ok(_execution_status(data, action), action)
        return data

    async def login(self, account, *, password=None, vercode=None):
        if bool(password) == bool(vercode):
            raise ValueError("Provide either password or email verification code")
        payload = {"by": "email-vercode" if vercode else "email-passwd", "account": account}
        payload["vercode" if vercode else "password"] = vercode if vercode else hashlib.md5(password.encode()).hexdigest()
        result = await self.request("login", "login", payload)
        self.token = result.get("token")
        return result.get("data")

    async def modify_password(self, account, vercode, password):
        return await self.request("login", "modify_pwd", {"account": account, "vercode": vercode,
                                                          "password": hashlib.md5(password.encode()).hexdigest()})

    async def email_vercode(self, to):
        return await self.request("vercode", "email", {"to": to})

    async def devices(self):
        return (await self.request("bluetooth", "list", {})).get("data")

    async def bind(self, eid):
        return await self.request("bluetooth", "bind", {"eid": eid})

    async def unbind(self, eid):
        return await self.request("bluetooth", "unbind", {"eid": eid})

    async def reset_pin(self, eid):
        """Account-side HTTP operation, not a BLE PIN command."""
        return await self.request("bluetooth", "reset_pin", {"eid": eid})

    async def save_nickname(self, nickname):
        return await self.request("user", "save", {"nickname": nickname})

    async def firmware_versions(self):
        return await self.request("firmware", "get_versions", {"key": FIRMWARE_KEY})

    async def firmware(self, name):
        return await self.request("firmware", "get_firmware", {"name": name, "key": FIRMWARE_KEY})

    async def check_pe(self, smdp):
        return await self.request("logger", "is_exclude_pe", {"smdpAddress": smdp})

    async def upload_logs(self, payload):
        """Explicit opt-in only; callers choose exactly which records to send."""
        return await self.request("logger", "save", payload)


class DirectRSP:
    """Optional direct transport, sharing the same async execute interface.

    TLS certificates are verified with the default urllib SSL context, matching
    the browser and the official WebAPI proxy path. GSMA payload signatures
    additionally protect the profile package, but transport verification is still
    required to keep activation codes / matching IDs / confirmation-code hashes
    confidential and to prevent tampering or denial of service. SM-DP+ servers
    use publicly trusted certificates; a private test CA must be added to the
    system trust store rather than disabling verification.
    """
    async def execute(self, action, smdp, protocol, fields):
        def perform():
            payload = dict(fields)
            if action == "initiateAuthentication":
                payload["smdpAddress"] = smdp
            request = urllib.request.Request(
                f"https://{smdp}/gsma/rsp2/es9plus/{action}",
                data=json.dumps(payload, separators=(",", ":")).encode(), method="POST",
                headers={"Content-Type": "application/json", "Accept": "application/json",
                         "X-Admin-Protocol": protocol, "User-Agent": "gsma-rsp-lpad"})
            with urllib.request.urlopen(request, timeout=40) as response:
                result = json.load(response)
            if not isinstance(result, dict):
                raise RuntimeError(f"ES9+ {action}: unexpected response")
            _require_ok(_execution_status(result, action), action)
            return result
        return await asyncio.to_thread(perform)
