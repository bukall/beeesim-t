#!/usr/bin/env python3
"""
beesim.py — Python BLE controller for BeeSIM eUICC cards.

Reverse-engineered from the official web LPA at https://beeesim.com/ble/
(Vue SPA, build "BeeSIM Web v2.3.6"). This re-implements, in Python, the
BLE transport framing and the GSMA SGP.22 (ES10) command set the web app sends
over Web Bluetooth.

The BeeSIM card is a GSMA Remote-SIM-Provisioning eUICC exposed over BLE:

  * BLE device name:   starts with "BeeSIM"
  * GATT service:      0000ae30-0000-1000-8000-00805f9b34fb  (16-bit 0xAE30)
  * Write char:        the service characteristic with WRITE / WRITE_NO_RESPONSE
  * Notify char:       the service characteristic with NOTIFY / INDICATE
  * Framing:           each ATT packet = [total_groups, group_index(1-based)] + up-to-18 payload bytes
  * Payload:           an ISO-7816 APDU (vendor A0.. commands, or STORE DATA / GET RESPONSE
                       carrying ES10 BER-TLV commands to the ISD-R applet)

Requires: pip install bleak

Card management uses BLE. Downloads and notification delivery also use HTTPS,
through the official Web 2.3.6 proxy by default, or directly to the SM-DP+.

USAGE:
  python beesim.py                                # launch the terminal UI (default)
  python beesim.py tui                            # ... same, explicitly
  python beesim.py scan
  python beesim.py info
  python beesim.py eid
  python beesim.py list
  python beesim.py enable   <iccid>
  python beesim.py disable  <iccid>
  python beesim.py delete   <iccid>
  python beesim.py rename   <iccid> "<nickname>"
  python beesim.py reset
  python beesim.py txpower  <0-4>                  # set BLE TX power (0=min, 4=max)
  python beesim.py notifications
  python beesim.py download "LPA:1$smdp$matchingId"   # download an eSIM profile
  python beesim.py apdu     A03F0000 00           # send a raw hex APDU (advanced)

The TUI (Textual) is optional: `pip install textual`. The CLI works with bleak
alone. The TUI also shows live BLE signal strength (RSSI). See README.md for the
full protocol documentation and a security note on the card's open BLE surface.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import List, Optional, Tuple

try:
    from bleak import BleakClient, BleakScanner
except ImportError:  # pragma: no cover
    BleakClient = BleakScanner = None  # allow --help / offline TLV work without bleak

# --------------------------------------------------------------------------- #
# Constants (verified from the web bundle)
# --------------------------------------------------------------------------- #
SERVICE_UUID = "0000ae30-0000-1000-8000-00805f9b34fb"
NAME_PREFIX = "BeeSIM"

# GSMA ISD-R AID selected on the logical channel (A4 04 00) before any ES10 cmd.
ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")

STORE_MAX_LC = 120          # Web 2.3.6 default; distinct from 18-byte BLE groups
GROUP_PAYLOAD = 18          # bytes of APDU per BLE packet          (groupValue)
LOGICAL_CHANNEL = 1         # fixed logical channel                 (pe.channel)


# --------------------------------------------------------------------------- #
# Small byte / BER-TLV helpers (ports of V, B, R, H, K, ce, be from the bundle)
# --------------------------------------------------------------------------- #
def h2b(hexstr: str) -> bytes:
    return bytes.fromhex("".join(hexstr.split()))


def b2h(data: bytes) -> str:
    return data.hex().upper()


def swap_nibbles(hexstr: str) -> str:
    """ICCID <-> on-card nibble-swapped form (JS `R`). Pads odd length with 'F'."""
    if len(hexstr) % 2:
        hexstr += "F"
    return "".join(hexstr[i + 1] + hexstr[i] for i in range(0, len(hexstr), 2))


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    if n <= 0xFFFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def tlv(tag, *children: bytes) -> bytes:
    """Build a BER-TLV (port of JS `H`): tag + length + concatenated children.

    `tag` may be an int (single byte) or a bytes/list of tag bytes.
    """
    if isinstance(tag, int):
        tag = bytes([tag])
    else:
        tag = bytes(tag)
    value = b"".join(children)
    return tag + der_len(len(value)) + value


def parse_tlv(data: bytes, start: int = 0, end: Optional[int] = None) -> list:
    """Recursive BER-TLV parser (port of JS `K`). Returns a list of nodes:
    {tag: 'HEX', length: int, value: bytes|list}. Constructed tags nest a list."""
    if end is None:
        end = len(data)
    if not 0 <= start <= end <= len(data):
        raise ValueError("Invalid TLV bounds")
    out = []
    i = start
    while i < end:
        tag_start = i
        constructed = (data[i] & 0x20) != 0
        if (data[i] & 0x1F) == 0x1F:  # multi-byte tag
            i += 1
            while i < end and (data[i] & 0x80):
                i += 1
            if i >= end:
                raise ValueError("Truncated TLV tag")
            i += 1
        else:
            i += 1
        tag = data[tag_start:i].hex().upper()
        # length
        if i >= end:
            raise ValueError("Missing TLV length")
        if data[i] & 0x80:
            nlen = data[i] & 0x7F
            i += 1
            if not nlen or i + nlen > end:
                raise ValueError("Invalid TLV length")
            length = 0
            for _ in range(nlen):
                length = (length << 8) | data[i]
                i += 1
        else:
            length = data[i]
            i += 1
        if i + length > end:
            raise ValueError(
                f"Truncated TLV value: tag {tag} needs {length} bytes, "
                f"only {end - i} remain at offset {i} "
                f"(data {data[start:start + 16].hex().upper()}...)")
        value_bytes = data[i:i + length]
        if constructed:
            value = parse_tlv(data, i, i + length)
        else:
            value = value_bytes
        out.append({"tag": tag, "length": length, "value": value})
        i += length
    return out


def find_tag(nodes: list, *tags: str):
    """Depth-first search through parsed TLV for a tag path (port of `be`/`ye`).
    Returns the matching node's value (bytes for primitive, list for constructed)."""
    current = nodes
    node = None
    for want in tags:
        node = _find_one(current, want)
        if node is None:
            return None
        current = node["value"] if isinstance(node["value"], list) else []
    if node is None:
        return None
    return node["value"]


def _find_one(nodes: list, want: str):
    nested = []
    for n in nodes:
        if n["tag"] == want:
            return n
        if isinstance(n["value"], list):
            nested.append(n)
    for n in nested:
        found = _find_one(n["value"], want)
        if found:
            return found
    return None


def serialize_tlv(node: dict) -> str:
    """Serialize a parsed node back to hex (port of JS `Ce`)."""
    if isinstance(node["value"], str):  # already-hex primitive (unused here)
        v = node["value"]
    elif isinstance(node["value"], bytes):
        v = node["value"].hex().upper()
    else:  # constructed
        v = "".join(serialize_tlv(c) for c in node["value"])
    tag = node["tag"]
    return tag + der_len(len(v) // 2).hex().upper() + v


# --------------------------------------------------------------------------- #
# BLE transport layer  (ports of Ye.open / writeBytes / writeGroupBytes / notify)
# --------------------------------------------------------------------------- #
class BeeSimTransport:
    """Low-level BLE link: discovers the AE30 service, chunk-frames APDUs out and
    reassembles the grouped notifications back into a full response (incl. SW)."""

    def __init__(self, client: "BleakClient", write_uuid: str, notify_uuid: str,
                 *, write_with_response: bool = False, timeout: float = 30.0):
        self.client = client
        self.write_uuid = write_uuid
        self.notify_uuid = notify_uuid
        self._buf = bytearray()
        self._future: Optional[asyncio.Future] = None
        self.write_with_response = write_with_response
        self.timeout = timeout
        self._lock = asyncio.Lock()
        self._expected = 1
        self._total = 0
        self._closed = False

    def disconnected(self, _client=None):
        self._closed = True
        if self._future and not self._future.done():
            self._future.set_exception(ConnectionError("BLE disconnected; reconnect the card"))

    # --- notification reassembly (port of toInitNotification handler) ---------
    def _on_notify(self, _char, data: bytearray):
        if self._future is None or self._future.done():
            return
        if len(data) < 2:
            self._future.set_exception(RuntimeError("Invalid BLE response frame"))
            return
        total, index = data[0], data[1]
        if not 1 <= index <= total or index != self._expected or (self._total and total != self._total):
            self._future.set_exception(RuntimeError("Out-of-order BLE response; reconnect the card"))
            return
        self._total = total
        self._expected += 1
        self._buf.extend(data[2:])
        if total == index:  # last group -> response complete
            if self._future and not self._future.done():
                self._future.set_result(bytes(self._buf))

    async def start(self):
        await self.client.start_notify(self.notify_uuid, self._on_notify)

    # --- outbound framing (port of groupValue + writeGroupBytes) --------------
    async def send(self, apdu: bytes, timeout: Optional[float] = None) -> bytes:
        async with self._lock:
            if self._closed:
                raise ConnectionError("BLE session unavailable; reconnect the card")
            groups = [apdu[i:i + GROUP_PAYLOAD] for i in range(0, len(apdu), GROUP_PAYLOAD)] or [b""]
            if len(groups) > 255:
                raise ValueError("APDU exceeds BLE framing limit")
            self._buf = bytearray()
            self._expected, self._total = 1, 0
            future = self._future = asyncio.get_running_loop().create_future()
            try:
                # Install the future BEFORE writing: some backends notify immediately.
                async with asyncio.timeout(self.timeout if timeout is None else timeout):
                    for idx, group in enumerate(groups, start=1):
                        await self.client.write_gatt_char(
                            self.write_uuid, bytes([len(groups), idx]) + group,
                            response=self.write_with_response,
                        )
                    return await future
            except BaseException:
                # A late response cannot be safely assigned to the next command.
                self._closed = True
                raise
            finally:
                if not future.done():
                    future.cancel()
                elif not future.cancelled():
                    future.exception()  # consume disconnect/write-race exceptions
                self._future = None


# --------------------------------------------------------------------------- #
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
            return await self.e.store_and_read(command)

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
            await self.remove_notification(data["index"])
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
# Profile-info parsing (port of Re/ze)
# --------------------------------------------------------------------------- #
def _child(node: dict, tag: str):
    if isinstance(node["value"], list):
        for c in node["value"]:
            if c["tag"] == tag:
                return c["value"]
    return None


def _parse_profile(e3: dict) -> dict:
    out = {}
    text = lambda v: bytes(v).decode("utf-8", "replace")
    for f in e3["value"]:
        t, v = f["tag"], f["value"]
        if t == "5A":
            out["iccid"] = swap_nibbles(b2h(v)).rstrip("F")
        elif t == "4F":
            out["isdpAid"] = b2h(v)
        elif t == "9F70":
            out["profileState"] = "ON" if v == b"\x01" else "OFF"
        elif t == "90":
            out["profileNickname"] = text(v)
        elif t == "91":
            out["serviceProviderName"] = text(v)
        elif t == "92":
            out["profileName"] = text(v)
        elif t == "95":
            out["profileClass"] = {b"\x01": "provisioning", b"\x02": "operational"}.get(v, "test")
        elif t == "93":
            out["iconType"] = "jpg" if v == b"\x01" else "png"
        elif t == "94":
            out["icon"] = base64.b64encode(v).decode()
        elif t in ("B6", "B7", "B8", "99"):
            key = {"B6": "notificationConfigurationInfo", "B7": "profileOwner",
                   "B8": "dpProprietaryData", "99": "profilePolicyRules"}[t]
            out[key] = _tlv_to_debug(v) if isinstance(v, list) else b2h(v)
    return out


def _parse_euicc_info(raw, root):
    nodes = parse_tlv(raw)
    if not nodes or nodes[0]["tag"] != root:
        raise RuntimeError("Invalid EUICCInfo response: " + b2h(raw))
    fields = {"82": "svn", "A9": "euiccCiPKIdListForVerification", "AA": "euiccCiPKIdListForSigning"}
    versions = {"82"}
    if root == "BF22":
        fields.update({"81": "profileVersion", "83": "euiccFirmwareVer", "84": "extCardResource",
                       "85": "uiccCapability", "86": "ts102241Version", "87": "globalplatformVersion",
                       "88": "rspCapability", "AB": "euiccCategory", "99": "forbiddenProfilePolicyRules",
                       "04": "ppVersion", "0C": "sasAcreditationNumber", "AC": "certificationDataObject"})
        versions |= {"81", "83", "86", "87", "04"}
    result = {}
    for node in nodes[0]["value"]:
        tag, value = node["tag"], node["value"]
        if tag not in fields:
            continue
        if tag in versions and isinstance(value, bytes):
            result[fields[tag]] = ".".join(str(x) for x in value)
        elif tag == "84":
            resources = parse_tlv(value) if isinstance(value, bytes) else value
            result[fields[tag]] = {name: int.from_bytes(find_tag(resources, t) or b"\x00", "big")
                                   for t, name in (("81", "installedApplication"), ("82", "freeNonVolatileMemory"), ("83", "freeVolatileMemory"))}
        elif tag == "0C":
            result[fields[tag]] = value.decode("utf-8", "replace")
        else:
            result[fields[tag]] = _tlv_to_debug(value) if isinstance(value, list) else b2h(value)
    result["raw"] = b2h(raw)
    return result


def _seq_bytes(seq):
    if isinstance(seq, int) and seq < 0:
        raise ValueError("Invalid notification sequence")
    value = _int_bytes(seq) if isinstance(seq, int) else h2b(seq)
    if not value:
        raise ValueError("Notification sequence missing")
    return value


def _notification_metadata(nodes):
    out = {}
    for node in nodes:
        tag, value = node["tag"], node["value"]
        if tag == "80":
            out["index"] = b2h(value)
        elif tag == "81":
            bits = int.from_bytes(value[1:], "big") if len(value) > 1 else 0
            out["profileManagementOperation"] = next((name for mask, name in ((128, "INSTALL"), (64, "ENABLE"), (32, "DISABLE"), (16, "DELETE")) if bits & mask), "UNKNOWN")
        elif tag == "0C":
            out["notificationAddress"] = value.decode("utf-8", "replace")
        elif tag == "5A":
            out["iccid"] = swap_nibbles(b2h(value)).rstrip("F")
    return out


def parse_installation_result(raw):
    nodes = parse_tlv(raw)
    data = find_tag(nodes, "BF37", "BF27")
    if not isinstance(data, list):
        raise RuntimeError("Invalid installation result: " + b2h(raw))
    metadata = find_tag(data, "BF2F")
    result = {"success": find_tag(data, "A2", "A0") is not None,
              "notificationMetadata": _notification_metadata(metadata or []), "raw": b2h(raw)}
    if not result["success"]:
        result["error"] = b2h(find_tag(data, "A2", "A1", "81") or b"") or "unknown"
    return result


def _int_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def _tlv_to_debug(nodes: list) -> dict:
    def conv(n):
        if isinstance(n["value"], list):
            return {n["tag"]: [conv(c) for c in n["value"]]}
        return {n["tag"]: b2h(n["value"])}
    return {"tlv": [conv(n) for n in nodes]}


# --------------------------------------------------------------------------- #
# BLE discovery + connection helper
# --------------------------------------------------------------------------- #
async def connect(address: Optional[str] = None, debug: bool = False, *,
                  timeout=30.0, store_max_lc=STORE_MAX_LC, channel=LOGICAL_CHANNEL,
                  delay_over_counter=6, log=None) -> Tuple["BleakClient", BeeSim, Euicc]:
    if BleakClient is None:
        raise RuntimeError("bleak is not installed. Run: pip install bleak")
    if address is None:
        if log:
            log("Scanning for BeeSIM…")
        else:
            print(f"Scanning for '{NAME_PREFIX}*' ...", file=sys.stderr)
        dev = await BleakScanner.find_device_by_filter(
            lambda d, ad: (d.name or "").startswith(NAME_PREFIX), timeout=15.0)
        if not dev:
            raise RuntimeError("No BeeSIM device found")
        address = dev.address
        if not log:
            print(f"Found {dev.name} @ {address}", file=sys.stderr)
    transport = euicc = None

    def disconnected(client):
        if transport:
            transport.disconnected(client)
        if euicc:
            euicc.inited = False

    client = BleakClient(address, disconnected_callback=disconnected)
    try:
        await client.connect()
        services = list(client.services)
        preferred = [s for s in services if s.uuid.lower() == SERVICE_UUID.lower()]
        candidates = preferred or [s for s in services if getattr(s, "is_primary", True)][:1]
        chars = [c for service in candidates for c in service.characteristics]
        writes = [c for c in chars if "write-without-response" in c.properties or "write" in c.properties]
        writes.sort(key=lambda c: "write-without-response" not in c.properties)
        notifies = [c for c in chars if "notify" in c.properties or "indicate" in c.properties]
        if not writes or not notifies:
            raise RuntimeError("Could not locate write/notify characteristics on AE30 service")
        write = writes[0]
        transport = BeeSimTransport(client, write.uuid, notifies[0].uuid,
                                    write_with_response="write-without-response" not in write.properties,
                                    timeout=timeout)
        euicc = Euicc(transport, debug=debug, channel=channel, store_max_lc=store_max_lc,
                      delay_over_counter=delay_over_counter)
        await transport.start()
        return client, BeeSim(euicc), euicc
    except BaseException:
        try:
            await client.disconnect()
        except Exception:
            pass
        raise

async def read_rssi(client) -> Optional[int]:
    """Best-effort RSSI (dBm) of the *connected* link, or None if unavailable.

    BeeSIM cards stop advertising once connected, so a passive scanner sees
    nothing — we must query the live connection. bleak exposes this on the
    platform backend: `client._backend.get_rssi()` (CoreBluetooth on macOS,
    BlueZ on Linux). Windows has no equivalent, so None there.
    """
    for target in (client, getattr(client, "_backend", None)):
        fn = getattr(target, "get_rssi", None) if target is not None else None
        if fn is None:
            continue
        try:
            val = fn()
            if asyncio.iscoroutine(val):
                val = await val
            if val is not None:
                return int(val)
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------- #
# eSIM download (Web 2.3.6 proxy or optional direct ES9+)
# --------------------------------------------------------------------------- #
def parse_activation_code(code: str) -> Tuple[str, str, bool]:
    """LPA:1$<smdp>$<matchingId>[$<oid>][$<ccRequired>] -> (smdp, matchingId, ccRequired)."""
    code = code.strip()
    if code.upper().startswith("LPA:"):
        code = code[4:]
    p = code.split("$")
    if len(p) < 2 or len(p) > 5 or p[0] != "1" or not re.fullmatch(r"[A-Za-z0-9.-]+", p[1]):
        raise ValueError("bad activation code; expected LPA:1$smdp$matchingId")
    return p[1], p[2] if len(p) > 2 else "", (len(p) > 4 and p[4] == "1")


def parse_firmware_text(text):
    """Parse the F0 rows / final F2 row and embedded version, as Web 2.3.6."""
    rows = [line.strip().upper() for line in text.splitlines() if line.strip()]
    if len(rows) < 2 or not rows[-1].startswith("F2") or any(not row.startswith("F0") for row in rows[:-1]):
        raise ValueError("Invalid firmware rows")
    for row in rows:
        h2b(row)
    marker = rows[-2].find("FEF0")
    if marker <= 0 or len(rows[-2][marker:]) < 18:
        raise ValueError("Firmware CRC missing")
    version = rows[-2][marker:]
    return {"rows": rows, "version": version, "crc": version[14:18]}


def _response_error(resp: bytes, root_tag: str) -> Optional[str]:
    """Return the error code of a top-level A1 (…ResponseError) in a BFxx response,
    or None. Only inspects DIRECT children (the A0 ok-branch nests its own A1s)."""
    nodes = parse_tlv(resp)
    if not nodes or nodes[0]["tag"] != root_tag or not isinstance(nodes[0]["value"], list):
        return None
    a1 = next((c for c in nodes[0]["value"] if c["tag"] == "A1"), None)
    if a1 is None:
        return None
    if isinstance(a1["value"], list):
        for c in a1["value"]:
            if c["tag"] == "02":
                return b2h(c["value"])
    return "??"


def _bpp_to_blocks(bpp: bytes) -> List[bytes]:
    """Segment a BoundProfilePackage into ES8+ STORE DATA blocks (SGP.22 §5.5.4)."""
    nodes = parse_tlv(bpp)
    if len(nodes) != 1 or nodes[0]["tag"] != "BF36" or not isinstance(nodes[0]["value"], list):
        raise ValueError("Invalid BoundProfilePackage")
    outer = nodes[0]
    hdr = outer["tag"] + der_len(outer["length"]).hex().upper()
    blocks: List[bytes] = []
    for seg in outer["value"]:
        tag = seg["tag"]
        if tag == "BF23":
            blocks.append(h2b(hdr + serialize_tlv(seg)))
        elif tag in ("A0", "A2"):
            blocks.append(h2b(serialize_tlv(seg)))
        elif tag in ("A1", "A3"):
            blocks.append(h2b(seg["tag"] + der_len(seg["length"]).hex().upper()))
            for child in seg["value"]:
                blocks.append(h2b(serialize_tlv(child)))
    return blocks


def _profile_meta(meta: bytes) -> dict:
    """Decode StoreMetadataRequest (BF25) enough to name the profile."""
    nodes = parse_tlv(meta)
    out = {}
    iccid = find_tag(nodes, "BF25", "5A") or find_tag(nodes, "5A")
    if iccid:
        out["iccid"] = swap_nibbles(b2h(iccid)).rstrip("F")
    for tag, key in (("92", "profileName"), ("91", "serviceProviderName")):
        v = find_tag(nodes, "BF25", tag) or find_tag(nodes, tag)
        if v:
            out[key] = bytes(v).decode("utf-8", "replace")
    return out


async def download_profile(sim: "BeeSim", euicc: "Euicc", smdp: str, matching_id: str = "",
                           confirm_code: Optional[str] = None, log=print, *, gateway=None) -> dict:
    """Web 2.3.6 download, installation-result validation and notification delivery.

    HTTP runs off the event loop. A failed notification is retained on the card
    for explicit retry; never download the profile again just to retry delivery.
    """
    from beesim_web import WebAPI
    gateway = gateway or WebAPI()
    b64e = lambda value: base64.b64encode(value).decode()
    b64d = lambda value: base64.b64decode(value, validate=True)
    async with euicc.transaction():
        await euicc.init()
        await euicc.set_tx_power(4)
        try:
            log("Reading challenge and EUICCInfo1…")
            challenge = await sim.get_euicc_challenge()
            if not challenge:
                raise RuntimeError("Challenge missing")
            info = await sim.get_euicc_info1()
            log("Authenticating server…")
            first = await gateway.execute("initiateAuthentication", smdp, sim.protocol,
                                          {"euiccChallenge": b64e(challenge), "euiccInfo1": b64e(h2b(info["raw"]))})
            transaction = first["transactionId"]
            auth = await sim.authenticate_server(b64d(first["serverSigned1"]), b64d(first["serverSignature1"]),
                                                 b64d(first["euiccCiPKIdToBeUsed"]), b64d(first["serverCertificate"]), matching_id)
            log("Authenticating client…")
            second = await gateway.execute("authenticateClient", smdp, sim.protocol,
                                           {"transactionId": transaction, "authenticateServerResponse": b64e(auth)})
            metadata = _profile_meta(b64d(second["profileMetadata"]))
            log("Preparing download…")
            prepared = await sim.prepare_download(b64d(second["smdpSigned2"]), b64d(second["smdpSignature2"]),
                                                  b64d(second["smdpCertificate"]), confirm_code)
            log("Downloading profile package…")
            third = await gateway.execute("getBoundProfilePackage", smdp, sim.protocol,
                                          {"transactionId": transaction, "prepareDownloadResponse": b64e(prepared)})
            log("Installing profile…")
            raw = await sim.load_bound_profile_package(b64d(third["boundProfilePackage"]))
            result = parse_installation_result(raw)
            log("Sending installation notification…")
            try:
                await gateway.execute("handleNotification", smdp, sim.protocol, {"pendingNotification": b64e(raw)})
            except Exception as exc:
                raise RuntimeError("Installation result received; notification pending. Refresh profiles and retry notification; do not repeat download") from exc
            if not result["success"]:
                raise RuntimeError("Installation failed: " + result["error"])
            index = result["notificationMetadata"].get("index")
            if index is None:
                raise RuntimeError("Installation notification index missing")
            await sim.remove_notification(index)
            log("Profile installed; notification delivered.")
            return dict(metadata, installationResult=result)
        finally:
            # Restore the lower power even when the download fails. Restoration
            # failure must not hide the original installation/notification error.
            try:
                await euicc.set_tx_power(1)
            except Exception:
                log("Could not restore TX power; reconnect and set power manually.")

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
async def _run(args):
    from beesim_web import DirectRSP, WebAPI
    gateway = DirectRSP() if args.rsp_transport == "direct" else WebAPI()
    if args.command == "web":
        import os
        payload = json.loads(Path(args.data_file).read_text()) if args.data_file else {}
        if not isinstance(payload, dict):
            raise ValueError("API payload must be a JSON object")
        result = await WebAPI(token=os.environ.get("BEESIM_TOKEN")).request(args.family, args.action, payload)
        result.pop("token", None)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    if args.command == "firmware-versions":
        print(json.dumps(await WebAPI().firmware_versions(), ensure_ascii=False, indent=2))
        return
    if args.command == "scan":
        if BleakScanner is None:
            raise RuntimeError("bleak not installed")
        devs = await BleakScanner.discover(timeout=8.0)
        found = [d for d in devs if (d.name or "").startswith(NAME_PREFIX)]
        for d in found:
            print(f"{d.address}  {d.name}")
        if not found:
            print("No BeeSIM devices found.")
        return

    client, sim, euicc = await connect(args.address, debug=args.debug, timeout=args.timeout,
                                      channel=args.channel, store_max_lc=args.store_max_lc,
                                      delay_over_counter=args.delay_over_counter)
    try:
        if args.command == "info":
            print("EID       :", await sim.get_eid())
            print("EUICCInfo1:", json.dumps(await sim.get_euicc_info1(), indent=2))
            print("EUICCInfo2:", json.dumps(await sim.get_euicc_info2(), indent=2))
        elif args.command == "eid":
            print(await sim.get_eid())
        elif args.command == "list":
            profiles = await sim.get_profiles(args.selector)
            print(json.dumps(profiles, indent=2, ensure_ascii=False))
        elif args.command == "enable":
            print("OK" if await sim.enable_profile(args.iccid) else "FAILED")
            await euicc.reset()
        elif args.command == "disable":
            print("OK" if await sim.disable_profile(args.iccid) else "FAILED")
            await euicc.reset()
        elif args.command == "delete":
            print("OK" if await sim.delete_profile(args.iccid) else "FAILED")
        elif args.command == "rename":
            print("OK" if await sim.set_nickname(args.iccid, args.nickname) else "FAILED")
        elif args.command == "reset":
            await euicc.reset()
            print("reset sent")
        elif args.command == "txpower":
            await euicc.set_tx_power(int(args.level))
            print("tx power set")
        elif args.command == "notifications":
            print(json.dumps(await sim.list_notifications(args.operation, decoded=True), ensure_ascii=False, indent=2))
        elif args.command == "notification-get":
            print(b2h(await sim.retrieve_notification(args.seq)))
        elif args.command == "notification-send":
            print(json.dumps(await sim.send_notification(args.seq, gateway), ensure_ascii=False, indent=2))
        elif args.command == "notification-remove":
            await sim.remove_notification(args.seq)
            print("OK")
        elif args.command == "firmware-status":
            print(json.dumps(await euicc.check_upgrading(), indent=2))
        elif args.command == "firmware-write":
            firmware = parse_firmware_text(Path(args.file).expanduser().read_text())
            progress = await euicc.check_upgrading()
            rows = firmware["rows"]
            start = 1
            if args.resume:
                if progress["crc"] != firmware["crc"] or progress["totalRows"] != len(rows):
                    raise ValueError("Firmware progress does not match this file")
                start = progress["currentRow"] + 1
            if start > len(rows):
                print("Firmware already complete")
            else:
                await sim.download_firmware(rows[start-1:], len(rows), start)
        elif args.command == "apdu":
            resp = await euicc.send_command(h2b(args.hex), reinit_on_6881=False)
            print(b2h(resp))
        elif args.command == "download":
            smdp, matching_id, cc_req = parse_activation_code(args.code)
            if cc_req and not args.confirm_code:
                raise ValueError("Confirmation code required (--confirm-code)")
            await download_profile(sim, euicc, smdp, matching_id, args.confirm_code, gateway=gateway)
    finally:
        await client.disconnect()


# --------------------------------------------------------------------------- #
# Terminal UI (Textual) — merged in; imported lazily so the CLI works without it
# --------------------------------------------------------------------------- #
def _build_tui_app():
    """Import Textual only when requested; inject this module for testability."""
    try:
        from beesim_tui import build_app
    except ImportError as exc:
        raise RuntimeError("The TUI needs Textual: pip install -r requirements.txt") from exc
    return build_app(sys.modules[__name__])


def run_tui(address=None, language=None, **options):
    _build_tui_app()(address=address, language=language, **options).run()


def main():
    p = argparse.ArgumentParser(description="BeeSIM BLE controller")
    p.add_argument("--address", help="BLE MAC/UUID (skip scan)")
    p.add_argument("--debug", action="store_true", help="log all APDU traffic to stderr")
    p.add_argument("--lang", choices=("zh", "en"), help="TUI language; omitted: choose at startup")
    p.add_argument("--timeout", type=float, default=30.0, help="APDU timeout in seconds (default: 30)")
    p.add_argument("--store-max-lc", type=int, default=120, help="STORE DATA bytes per block (default: 120)")
    p.add_argument("--channel", type=int, choices=(1, 2, 3), default=1)
    p.add_argument("--delay-over-counter", type=int, default=6, help="throttle threshold; 0 disables")
    p.add_argument("--rsp-transport", choices=("web", "direct"), default="web", help="official Web proxy (default) or direct SM-DP+")
    sub = p.add_subparsers(dest="command")
    tui = sub.add_parser("tui", help="launch the terminal UI (default when no command given)")
    tui.add_argument("--lang", choices=("zh", "en"), default=argparse.SUPPRESS)
    sub.add_parser("scan")
    sub.add_parser("info")
    sub.add_parser("eid")
    profiles = sub.add_parser("list")
    profiles.add_argument("--selector", help="hex tag list (5C...) or ISD-P AID")
    for c in ("enable", "disable", "delete"):
        sp = sub.add_parser(c)
        sp.add_argument("iccid")
    sp = sub.add_parser("rename"); sp.add_argument("iccid"); sp.add_argument("nickname")
    sub.add_parser("reset")
    sp = sub.add_parser("txpower", help="set the card's BLE TX power (0-4)")
    sp.add_argument("level", type=int, choices=range(5))
    notifications = sub.add_parser("notifications")
    notifications.add_argument("--operation", choices=("INSTALL", "ENABLE", "DISABLE", "DELETE"))
    for command in ("notification-get", "notification-send", "notification-remove"):
        notification = sub.add_parser(command)
        notification.add_argument("seq", nargs="?" if command == "notification-get" else None, help="hex sequence; get without seq retrieves all")
    sub.add_parser("firmware-status")
    sub.add_parser("firmware-versions")
    firmware = sub.add_parser("firmware-write", help="write a local vendor firmware text file")
    firmware.add_argument("file")
    firmware.add_argument("--resume", action="store_true")
    firmware.add_argument("--yes", action="store_true", help="confirm firmware write")
    web = sub.add_parser("web", help="official HTTP API; payload is a JSON file, token from BEESIM_TOKEN")
    web.add_argument("family", choices=("rsp", "firmware", "login", "bluetooth", "vercode", "user", "logger"))
    web.add_argument("action")
    web.add_argument("--data-file")
    sp = sub.add_parser("apdu"); sp.add_argument("hex")
    sp = sub.add_parser("download", help="download an eSIM (LPA activation code / QR)")
    sp.add_argument("code", help="LPA:1$smdp$matchingId  (or a bare 1$smdp$matchingId)")
    sp.add_argument("--confirm-code", dest="confirm_code")
    args = p.parse_args()
    if not 0 < args.timeout <= 300 or not 1 <= args.store_max_lc <= 255 or args.delay_over_counter < 0:
        p.error("Invalid timeout, STORE DATA size or throttle threshold")
    if args.command == "firmware-write" and not args.yes:
        p.error("Firmware writing requires --yes")

    # No sub-command (or an explicit `tui`) -> launch the terminal UI.
    if args.command in (None, "tui"):
        # TUI downloads always make the selected route visible in a confirmation.
        from beesim_web import DirectRSP
        run_tui(args.address, args.lang, debug=args.debug,
                settings=dict(timeout=args.timeout, store_max_lc=args.store_max_lc,
                              channel=args.channel, delay_over_counter=args.delay_over_counter),
                gateway=DirectRSP() if args.rsp_transport == "direct" else None)
    else:
        try:
            asyncio.run(_run(args))
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"Error: {exc or type(exc).__name__}", file=sys.stderr)
            raise SystemExit(1) from None


if __name__ == "__main__":
    main()
