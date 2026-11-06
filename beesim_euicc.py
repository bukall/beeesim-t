"""
eUICC 会话层：Euicc（APDU / 逻辑通道）与 BeeSim（ES10 命令集）。

类与职责
--------
  Euicc  管理一次 BLE 会话内的 APDU：初始化（CLOSE -> 设备特性 -> OPEN ->
         SELECT ISD-R）、STORE DATA 分块写入、GET RESPONSE 链、厂商命令
         （功率 / 复位 / 固件进度）、节流与事务串行化。
  BeeSim 把 ES10 命令包装成高层方法：EID、EUICCInfo1/2、配置列表、启用/停用/
         删除/改名、通知列表/检索/发送/删除、下载流程的卡侧步骤、固件刷写。

数据流（一次读命令）
--------------------
  BeeSim._read(cmd_tlv)
    -> Euicc.store_and_read()   # 事务内：init -> store_bytes -> get_response
       -> store_bytes(): 81 E2 <11|91> <block> <Lc> <data> 分块
       -> get_response(): 81 C0 00 00 <Le> 循环，61xx 继续 / 9000 结束
    -> 返回纯 TLV 数据（已剥离 SW1SW2）
    -> parse_tlv + 业务解析（在 beesim_protocol）

关键行为
--------
* 空 9000（卡片下一分段未就绪）最多重发 3 次，否则会返回半截 TLV。
* 只读 ES10 命令（_REPLAYABLE_ES10_TAGS 白名单）在响应 TLV 不完整时自动重读
  最多 3 次；写命令与下载流程绝不重放，避免重复执行。
* 节流：累计 N 条 APDU 后暂停 1.2s（GET RESPONSE 0xC0 与 0xFE 不计数）；
  下载配置包 / 刷固件时临时提高到 20。
* 发送通知成功后，INSTALL/ENABLE/DISABLE 通知会被删除，DELETE（删卡）通知
  保留在卡上——这是与官方 Web 有意不同的行为，见 web-api-reference.json。

依赖：beesim_tlv、beesim_protocol、beesim_web（仅函数内延迟 import）。
不依赖 bleak / textual / CLI / TUI，便于用模拟 transport 做单元测试。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import sys
from contextlib import asynccontextmanager
from typing import List, Optional, TYPE_CHECKING

from beesim_protocol import (
    ISDR_AID, LOGICAL_CHANNEL, STORE_MAX_LC,
    _bpp_to_blocks, _notification_metadata, _parse_euicc_info, _parse_profile,
    _response_error, _seq_bytes, parse_installation_result,
)
from beesim_tlv import (
    b2h, find_tag, h2b, parse_tlv, serialize_tlv, swap_nibbles, tlv,
    _child, _tlv_response_complete,
)

if TYPE_CHECKING:  # avoids a runtime cycle: transport imports this module
    from beesim_transport import BeeSimTransport

# eUICC command layer  (ports of pe/G: channel, SELECT, STORE DATA, GET RESPONSE)
# --------------------------------------------------------------------------- #
class Euicc:
    def __init__(self, transport: BeeSimTransport, debug: bool = False, *,
                 channel: int = LOGICAL_CHANNEL, store_max_lc: int = STORE_MAX_LC,
                 delay_over_counter: int = 6):
        if not 1 <= channel <= 3:
            raise ValueError("Logical channel must be 1..3 for the Web APDU encoding")
        if not 1 <= store_max_lc <= 255 or delay_over_counter < 0:
            raise ValueError("Invalid APDU settings")
        self.t = transport
        self.channel = channel
        self.store_max_lc = store_max_lc
        self.delay_over_counter = delay_over_counter
        self._counter = 0
        self._lock = asyncio.Lock()
        self._owner = None
        self.inited = False
        self.debug = debug
        self.on_log = None  # optional callback(str) — used by the TUI

    @asynccontextmanager
    async def transaction(self):
        """Serialize whole STORE/READ and download sequences, allowing nested calls."""
        task = asyncio.current_task()
        if self._owner is task:
            yield
            return
        async with self._lock:
            self._owner = task
            try:
                yield
            except BaseException:
                self.inited = False
                raise
            finally:
                self._owner = None

    def _log(self, *a):
        if self.on_log is not None:
            self.on_log(" ".join(str(x) for x in a))
        if self.debug:
            print("[euicc]", *a, file=sys.stderr)

    async def send_command(self, apdu: bytes, reinit_on_6881: bool = True) -> bytes:
        async with self.transaction():
            return await self._send_command(apdu, reinit_on_6881)

    async def _send_command(self, apdu: bytes, reinit_on_6881: bool = True) -> bytes:
        if len(apdu) < 4:
            raise ValueError("APDU requires a four-byte header")
        if self.delay_over_counter and reinit_on_6881:
            if self._counter >= self.delay_over_counter and apdu[1] not in (0xC0, 0xFE):
                await asyncio.sleep(1.2)
                self._counter = 0
            else:
                self._counter += 1
        self._log("-->", b2h(apdu))
        resp = await self.t.send(apdu)
        self._log("<--", b2h(resp))
        if reinit_on_6881 and len(resp) >= 2 and resp[-2] == 0x68 and resp[-1] == 0x81:
            # "logical channel not supported" -> re-open channel and retry once
            self.inited = False
            await self.init()
            resp = await self.t.send(apdu)
            self._log("<-- (retry)", b2h(resp))
        return resp

    # --- vendor commands (CLA 0xA0) ------------------------------------------
    async def set_tx_power(self, power: int = 1):
        """A0 3E <power> 00 00 — set BLE TX power. Valid 0-4 (0=min, 4=max;
        levels 5-7 are meaningless). Web app uses 4 during install."""
        if power not in range(5):
            raise ValueError("TX power must be 0..4")
        r = await self.send_command(bytes([0xA0, 0x3E, power, 0x00, 0x00]), reinit_on_6881=False)
        if r[-2:] != b"\x90\x00":
            raise RuntimeError("Set TX power failed: " + b2h(r))

    async def reset(self):
        """A0 3F 00 00 00 — soft reset of the eUICC (re-does ATR/refresh)."""
        try:
            await self.send_command(bytes([0xA0, 0x3F, 0x00, 0x00, 0x00]), reinit_on_6881=False)
        finally:
            self.inited = False

    async def check_upgrading(self) -> dict:
        """00 00 00 00 F4 01 01 — vendor firmware-progress query."""
        r = await self.send_command(bytes([0x00, 0x00, 0x00, 0x00, 0xF4, 0x01, 0x01]), reinit_on_6881=False)
        if len(r) >= 55 and r[0] == 0x10:
            return {
                "crc": b2h(r[49:51]),
                "totalRows": int.from_bytes(r[51:53], "big"),
                "currentRow": int.from_bytes(r[53:55], "big"),
            }
        raise RuntimeError("check_upgrading failed: " + b2h(r))

    # --- logical channel + ISD-R select (port of openChannel/selectApplication)
    async def open_channel(self):
        ch = self.channel
        await self.send_command(bytes([0x00, 0x70, 0x80, ch, 0x00]), reinit_on_6881=False)  # close ch
        # vendor "device features" GET DATA
        await self.send_command(h2b("80AA00000AA9088100820101830107"), reinit_on_6881=False)
        r = await self.send_command(bytes([0x00, 0x70, 0x00, ch, 0x00]), reinit_on_6881=False)  # open ch
        # Web 2.3.6 proceeds to SELECT even on 6A86. An already usable channel
        # can reject OPEN. Validate SELECT before declaring the session usable.
        self._open_status = r
        if r[-2:] != b"\x90\x00":
            self._log("OPEN status", b2h(r), "— verifying SELECT ISD-R")

    async def select_isdr(self):
        apdu = bytes([self.channel, 0xA4, 0x04, 0x00, len(ISDR_AID)]) + ISDR_AID
        r = await self.send_command(apdu, reinit_on_6881=False)
        if len(r) >= 2 and r[-2] == 0x61:
            return await self.get_response(r[-1])
        if r[-2:] != b"\x90\x00":
            raise RuntimeError("SELECT ISD-R failed: " + b2h(r) +
                               "; OPEN status: " + b2h(getattr(self, "_open_status", b"")))

    async def init(self):
        async with self.transaction():
            if self.inited:
                return
            await self.open_channel()
            await self.select_isdr()
            self.inited = True

    # --- GET RESPONSE loop (port of readBytesFromEUICC) -----------------------
    async def get_response(self, le: int, retries: int = 0) -> bytes:
        async with self.transaction():
            return await self._get_response(le)

    async def _get_response(self, le: int) -> bytes:
        cla = (self.channel & 0x0F) | 0x80
        buf = bytearray()
        ins = 0xC0
        empty_replies = 0
        for _ in range(1024):
            r = await self.send_command(bytes([cla, ins, 0x00, 0x00, le]))
            if len(r) < 2:
                raise RuntimeError("Truncated GET RESPONSE: " + b2h(r))
            body, sw1, sw2 = r[:-2], r[-2], r[-1]
            if sw1 == 0x61:                 # more data available
                buf.extend(body)
                le = sw2
                ins = 0xC0
            elif sw1 == 0x90:               # done
                if not body and empty_replies < 3:
                    # Web 2.3.6 retries an empty 90 00: the card may not have
                    # the next segment ready yet. Returning here would hand a
                    # partial TLV to parse_tlv ("Truncated TLV value").
                    empty_replies += 1
                    self._log("<-- empty 90 00, retry", empty_replies)
                    continue
                buf.extend(body)
                return bytes(buf)
            elif sw1 == 0xFE or sw2 == 0xFE:
                ins = 0xFE
            elif sw1 == 0x6C:  # wrong Le -> resend with sw2
                le = sw2
            else:
                self.inited = False
                raise RuntimeError("GET RESPONSE error: " + b2h(r))
        raise RuntimeError("GET RESPONSE exceeded response limit")

    # --- STORE DATA chaining (port of storeBytesToEUICC) ----------------------
    async def store_bytes(self, data: bytes) -> bytes:
        async with self.transaction():
            return await self._store_bytes(data)

    async def _store_bytes(self, data: bytes) -> bytes:
        cla = (self.channel & 0x0F) | 0x80
        block = 0
        pos = 0
        while True:
            remaining = data[pos:]
            more = len(remaining) > self.store_max_lc
            chunk = remaining[:self.store_max_lc] if more else remaining
            p1 = 0x11 if more else 0x91
            apdu = bytes([cla, 0xE2, p1, block, len(chunk)]) + chunk
            r = await self.send_command(apdu)
            if len(r) < 2:
                raise RuntimeError("Truncated STORE DATA response")
            if not more and r[-2] == 0x61:
                return r[-2:]
            if r[-2:] == b"\x90\x00" or (more and r[-2:] == b"\x00\xfe"):
                if more:
                    block += 1
                    pos += self.store_max_lc
                    if block > 255:
                        raise ValueError("STORE DATA block counter overflow")
                    continue
                return r
            if not more and r[-1] == 0xFE:
                return bytes([0x61 if r[-2] else 0x90, r[-2]])
            self.inited = False
            raise RuntimeError("STORE DATA error: " + b2h(r))

    async def store_and_read(self, data: bytes) -> bytes:
        """Send an ES10 command TLV and return its full response TLV (port of storeAndReadBytes)."""
        async with self.transaction():
            await self.init()
            r = await self.store_bytes(data)
            if r and r[0] == 0x61:
                return await self.get_response(r[1])
            raise RuntimeError("store_and_read: unexpected " + b2h(r))


# --------------------------------------------------------------------------- #
# ES10 API — the high-level "APIs" the web app exposes (ports of the `Ve` object)
# --------------------------------------------------------------------------- #
# Read-only ES10 commands (tag prefix) that are safe to replay when the card
# returns an incomplete chained response. State-changing commands and the
# download sequence must never be replayed automatically.
_REPLAYABLE_ES10_TAGS = {"BF20", "BF22", "BF2D", "BF2E", "BF28", "BF2B", "BF3E"}


class BeeSim:
    def __init__(self, euicc: Euicc):
        self.e = euicc
        self.svn = "2.2.2"

    @property
    def protocol(self):
        return "gsma/rsp/v" + self.svn

    async def _read(self, command: bytes):
        async with self.e.transaction():
            self.e._counter = 0
            attempts = 3 if command[:2].hex().upper() in _REPLAYABLE_ES10_TAGS else 1
            raw = b""
            for attempt in range(attempts):
                raw = await self.e.store_and_read(command)
                if attempts == 1 or _tlv_response_complete(raw):
                    return raw
                self.e._log("incomplete TLV response; re-reading", attempt + 1)
                await asyncio.sleep(0.2)
            return raw

    async def get_euicc_info1(self) -> dict:
        raw = await self._read(h2b("BF2000"))
        info = _parse_euicc_info(raw, "BF20")
        self.svn = info.get("svn", self.svn)
        return info

    # -- ES10c: identity & profiles -------------------------------------------
    async def get_eid(self) -> str:
        # BF 3E 03 5C 01 5A  (GET DATA, tag list = EID)
        r = await self._read(bytes([0xBF, 0x3E, 0x03, 0x5C, 0x01, 0x5A]))
        eid = find_tag(parse_tlv(r), "BF3E", "5A")
        if eid is None:
            raise RuntimeError("EID not found: " + b2h(r))
        return b2h(eid)

    async def get_euicc_info2(self) -> dict:
        r = await self._read(h2b("BF2200"))
        info = _parse_euicc_info(r, "BF22")
        self.svn = info.get("svn", self.svn)
        return info

    async def get_profiles(self, selector: Optional[str] = None) -> List[dict]:
        # BF 2D 00  (get all ProfileInfo)
        command = h2b("BF2D00")
        if selector:
            value = h2b(selector)
            command = tlv([0xBF, 0x2D], value if value[0] == 0x5C else
                          tlv(0xA0, tlv(0x4F, value)) + h2b("5C075A9F7090919295"))
        r = await self._read(command)
        nodes = parse_tlv(r)
        if not (nodes and nodes[0]["tag"] == "BF2D"):
            raise RuntimeError("GetProfilesInfo failed: " + b2h(r))
        profiles = []
        a0 = _child(nodes[0], "A0")
        if a0:
            for e3 in a0:
                if e3["tag"] == "E3":
                    profiles.append(_parse_profile(e3))
        return profiles

    async def enable_profile(self, iccid: str) -> bool:
        cmd = tlv([0xBF, 0x31], tlv([0xA0], tlv([0x5A], h2b(swap_nibbles(iccid)))), bytes([0x81, 0x01, 0x00]))
        return await self._result(cmd, "EnableProfile")

    async def disable_profile(self, iccid: str) -> bool:
        cmd = tlv([0xBF, 0x32], tlv([0xA0], tlv([0x5A], h2b(swap_nibbles(iccid)))), bytes([0x81, 0x01, 0x00]))
        return await self._result(cmd, "DisableProfile")

    async def delete_profile(self, iccid: str) -> bool:
        cmd = tlv([0xBF, 0x33], tlv([0x5A], h2b(swap_nibbles(iccid))))
        return await self._result(cmd, "DeleteProfile")

    async def set_nickname(self, iccid: str, nickname: str) -> bool:
        cmd = tlv([0xBF, 0x29], tlv([0x5A], h2b(swap_nibbles(iccid))), tlv([0x90], nickname.encode("utf-8")))
        r = await self._read(cmd)
        code = find_tag(parse_tlv(r), "BF29", "80")
        if code == b"\x00":
            return True
        raise RuntimeError(f"SetNickname failed (code={b2h(code) if code else '??'})")

    async def _result(self, cmd: bytes, name: str) -> bool:
        r = await self._read(cmd)
        code = find_tag(parse_tlv(r), "80")
        if code == b"\x00" or (name == "EnableProfile" and code == b"\x02"):
            return True
        msgs = {1: "not-exist", 2: "wrong-state", 3: "policy-forbidden", 4: "profile-error", 5: "busy"}
        c = code[0] if code else -1
        raise RuntimeError(f"{name} failed: {msgs.get(c, 'code ' + str(c))}")

    # -- ES10b: notifications --------------------------------------------------
    async def list_notifications(self, operation: Optional[str] = None, *, decoded=False):
        operations = {"INSTALL": b"\x07\x80", "ENABLE": b"\x06\x40",
                      "DISABLE": b"\x05\x20", "DELETE": b"\x04\x10"}
        if operation and operation.upper() not in operations:
            raise ValueError("Unknown notification operation")
        command = tlv([0xBF, 0x28], tlv(0x81, operations[operation.upper()])) if operation else h2b("BF2800")
        raw = await self._read(command)
        if not decoded:
            return raw
        nodes = parse_tlv(raw)
        items = find_tag(nodes, "BF28", "A0")
        if not isinstance(items, list):
            raise RuntimeError("ListNotification failed: " + b2h(raw))
        return [_notification_metadata(n["value"]) for n in items if n["tag"] == "BF2F"]

    async def retrieve_notification(self, seq=None) -> bytes:
        command = h2b("BF2B00") if seq is None else tlv([0xBF, 0x2B], tlv(0xA0, tlv(0x80, _seq_bytes(seq))))
        return await self._read(command)

    async def remove_notification(self, seq) -> bool:
        r = await self._read(tlv([0xBF, 0x30], tlv(0x80, _seq_bytes(seq))))
        code = find_tag(parse_tlv(r), "80")
        # Web bundle: 00 = removed, 01 = nothing to delete ("notification not found").
        if code == b"\x01":
            raise RuntimeError("Notification not found")
        if code != b"\x00":
            raise RuntimeError("RemoveNotificationFromList failed: " + b2h(code or b""))
        return True

    async def authenticate_server(self, signed, signature, ci_key, certificate, matching_id=""):
        context = (tlv(0x80, matching_id.encode()) if matching_id else b"") + h2b("A108800435290611A100")
        raw = await self._read(tlv([0xBF, 0x38], signed, signature, ci_key, certificate, tlv(0xA0, context)))
        error = _response_error(raw, "BF38")
        if error:
            raise RuntimeError("AuthenticateServer rejected: " + error)
        return raw

    async def prepare_download(self, signed, signature, certificate, confirmation_code=None):
        nodes = parse_tlv(signed)
        required = find_tag(nodes, "30", "01") == b"\xff"
        if required and not confirmation_code:
            raise ValueError("Confirmation code required")
        fields = [signed, signature]
        if confirmation_code:
            transaction_id = find_tag(nodes, "30", "80")
            if not transaction_id:
                raise ValueError("Signed transaction ID missing")
            fields.append(tlv(4, hashlib.sha256(hashlib.sha256(confirmation_code.encode()).digest() + transaction_id).digest()))
        fields.append(certificate)
        raw = await self._read(tlv([0xBF, 0x21], *fields))
        error = _response_error(raw, "BF21")
        if error:
            raise RuntimeError("PrepareDownload rejected: " + error)
        return raw

    async def load_bound_profile_package(self, package):
        async with self.e.transaction():
            await self.e.init()
            previous = self.e.delay_over_counter
            try:
                self.e.delay_over_counter = 20
                for block in _bpp_to_blocks(package):
                    response = await self.e.store_bytes(block)
                    if response[0] == 0x61:
                        raw = await self.e.get_response(response[1])
                        parse_installation_result(raw)
                        return raw
                    if response[-2:] != b"\x90\x00":
                        raise RuntimeError("LoadBoundProfilePackage failed: " + b2h(response))
                raise RuntimeError("Installation result missing")
            finally:
                self.e.delay_over_counter = previous

    async def send_notification(self, seq, gateway=None):
        from beesim_web import WebAPI
        async with self.e.transaction():
            raw = await self.retrieve_notification(seq)
            items = find_tag(parse_tlv(raw), "BF2B", "A0")
            if not items:
                raise RuntimeError("Notification not found")
            node = items[0]
            metadata = find_tag([node], "BF2F")
            if not isinstance(metadata, list):
                raise RuntimeError("Notification metadata missing")
            data = _notification_metadata(metadata)
            smdp = data.get("notificationAddress")
            if not smdp:
                raise RuntimeError("Notification address missing")
            if smdp == "rsp.simhub.cn":
                smdp = "rsp-eu.redteamobile.com"
            pending = h2b(serialize_tlv(node))
            await (gateway or WebAPI()).execute("handleNotification", smdp, self.protocol,
                                               {"pendingNotification": base64.b64encode(pending).decode()})
            # The Web bundle deletes by the sequence the caller requested, not
            # by the index parsed out of the notification body. It also always
            # removes the notification after a successful send. This client
            # deliberately differs for DELETE (profile removal) notifications:
            # those stay on the card so the owner keeps an audit record.
            if data.get("profileManagementOperation") != "DELETE":
                await self.remove_notification(seq)
            return data

    async def download_firmware(self, rows, total=None, start=1, log=print):
        total = len(rows) if total is None else total
        if not rows or not 1 <= start <= total <= 65535 or len(rows) != total - start + 1:
            raise ValueError("Invalid firmware range")
        # Web M(n) is a big-endian 16-bit field; rows contain the vendor header.
        async with self.e.transaction():
            previous = self.e.delay_over_counter
            try:
                self.e.delay_over_counter = 20
                for index, row in enumerate(rows, start):
                    response = await self.e.send_command(total.to_bytes(2, "big") + index.to_bytes(2, "big") + h2b(row))
                    if len(response) < 4 or response[0] != 0x10 or response[3] != 1:
                        raise RuntimeError(f"Firmware write failed at {index}/{total}: {b2h(response)}")
                    log(f"{index}/{total}")
                await self.e.reset()
            finally:
                self.e.delay_over_counter = previous

    async def get_euicc_challenge(self) -> bytes:
        r = await self._read(bytes([0xBF, 0x2E, 0x00]))
        return find_tag(parse_tlv(r), "80")

    async def set_tx_power(self, power: int) -> None:
        """Set the card's BLE transmit power (0-4, 0=min/4=max; vendor A0 3E).
        Convenience wrapper around the eUICC-level command."""
        await self.e.set_tx_power(power)


# --------------------------------------------------------------------------- #

