"""
BLE 传输层：GATT 连接、18 字节分组帧、通知重组、超时与断连处理。

职责
----
* BeeSimTransport：把一条 APDU 切成 18 字节组并加 2 字节头写出；把卡片 notify
  回来的分组按序号重组为完整响应（含末尾 SW1SW2）。
* connect()：扫描或直连 BeeSIM 卡，按属性挑选 write / notify 特征，建立会话，
  返回 (BleakClient, BeeSim, Euicc)。
* read_rssi()：尽力读取已连接链路的 RSSI。Windows 的 WinRT BluetoothLEDevice
  不提供已连接设备 RSSI（RSSI 只在广播阶段可得，而卡片连接后停止广播），
  因此 Windows 恒返回 None——这是平台限制，不是本层缺陷；macOS / Linux 可读取。

帧格式（官方 Web 2.3.6）
------------------------
  每个 ATT 包 = [total_groups, group_index(1-based)] + 最多 18 字节 APDU
  重组：index==1 时清空缓冲；index==total 时响应结束；乱序或断连立即报错。

重要不变量（维护者 / AI 请先读）
--------------------------------
* 请求必须串行：send() 内部 asyncio.Lock，一个 future 只对应一次写-读周期。
* 超时后 transport 永久标记 _closed，必须重新 connect()：迟到的响应不能被
  误认为下一条命令的结果。
* disconnected() 会唤醒挂起的 future 并抛 ConnectionError。
* bleak 为可选依赖：import 失败时 BleakClient/BleakScanner 置 None，
  保证 --help 与离线 TLV 工具仍可使用。
"""

from __future__ import annotations

import asyncio
import sys
from typing import Optional, Tuple

from beesim_protocol import (
    GROUP_PAYLOAD, LOGICAL_CHANNEL, NAME_PREFIX, SERVICE_UUID, STORE_MAX_LC,
)
from beesim_euicc import BeeSim, Euicc


try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError
    _BLE_RETRY_ERRORS: tuple = (TimeoutError, ConnectionError, OSError, BleakError)
except ImportError:  # pragma: no cover
    # Optional dependency; the names stay usable as sentinels for "not installed".
    BleakClient = BleakScanner = None  # type: ignore[assignment, misc]
    _BLE_RETRY_ERRORS = (TimeoutError, ConnectionError, OSError)

# BLE transport layer  (connect / write bytes / grouped write / notify reassembly)
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

    @property
    def closed(self) -> bool:
        """True once the session is invalidated (timeout/disconnect); reconnect required."""
        return self._closed

    def disconnected(self, _client=None):
        self._closed = True
        if self._future and not self._future.done():
            self._future.set_exception(ConnectionError("BLE disconnected; reconnect the card"))

    # --- notification reassembly ----------------------------------------------
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

    # --- outbound framing -----------------------------------------------------
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

# --------------------------------------------------------------------------- #
# BLE discovery + connection helper
# --------------------------------------------------------------------------- #
async def connect(address: Optional[str] = None, debug: bool = False, *,
                  timeout=30.0, store_max_lc=STORE_MAX_LC, channel=LOGICAL_CHANNEL,
                  delay_over_counter=6, log=None) -> Tuple["BleakClient", BeeSim, Euicc]:
    if BleakClient is None:
        raise RuntimeError("bleak is not installed. Run: pip install bleak")

    # --- 解析设备对象（只做一次；避免重试时重复扫描，设备未广播时也快速失败）---
    device = None
    if address is None:
        if log:
            log("Scanning for BeeSIM…")
        else:
            print(f"Scanning for '{NAME_PREFIX}*' ...", file=sys.stderr)
        device = await BleakScanner.find_device_by_filter(
            lambda d, ad: (d.name or "").startswith(NAME_PREFIX), timeout=15.0)
        if not device:
            raise RuntimeError("No BeeSIM device found")
        addr = device.address
        if not log:
            print(f"Found {device.name} @ {addr}", file=sys.stderr)
    else:
        # Windows/WinRT：用裸地址做 GATT 服务发现可能挂起/超时（卡片换卡槽断电、
        # GATT 缓存失效后尤甚）。先短暂扫描把地址解析成 BLEDevice 对象再连接；未广播
        # （被其它连接占用/未上电）则快速失败，不做裸地址连接的长等待。
        addr = address
        find = getattr(BleakScanner, "find_device_by_address", None)
        if find is not None:
            device = await find(address, timeout=min(timeout, 10.0))
            if device is None:
                raise RuntimeError(f"No BeeSIM device found at {address}")

    transport = euicc = None

    def disconnected(client):
        # 仅当断开回调来自"当前会话的 client"时才处理。重试时此回调被多次 _open
        # 共享，旧 client 的延迟断开回调若不加身份校验会误关新会话。
        if transport is not None and getattr(transport, "client", None) is client:
            transport.disconnected(client)
            if euicc:
                euicc.inited = False

    async def _open():
        nonlocal transport, euicc
        transport = euicc = None
        # 传 BLEDevice 对象（而非裸地址字符串）：WinRT 借此复用刚发现的设备上下文，
        # 避免裸地址 GATT 发现挂起（TimeoutError / WinError -2147023673）。
        client = BleakClient(device if device is not None else addr,
                             disconnected_callback=disconnected)
        try:
            await client.connect()
            services = list(client.services)
            preferred = [s for s in services if s.uuid.lower() == SERVICE_UUID.lower()]
            if not preferred:
                # 官方 Web 明确请求 AE30 服务；缺失时不得回退到无关主服务，否则
                # EID/配置/删除/刷固件等 APDU 可能被发往错误 GATT 服务。
                raise RuntimeError("BeeSIM AE30 service not found")
            chars = [c for service in preferred for c in service.characteristics]
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

    # 卡片断电重启（换卡槽）后 Windows/WinRT 连接可能瞬时失败（超时/初始化掉线/设备
    # 暂不可达）；仅对"连接 + 会话建立"重试几次，与官方网页的重连效果一致。设备解析
    # 已在上面一次性完成，扫描失败（无适配器/未广播）不在此重试。
    for attempt in range(3):
        try:
            return await _open()
        except _BLE_RETRY_ERRORS as exc:
            if attempt == 2:
                raise
            msg = f"Connect attempt {attempt + 1} failed ({exc or type(exc).__name__}); retrying…"
            if log:
                log(msg)
            else:
                print(msg, file=sys.stderr)
            await asyncio.sleep(2.0)
            # 重试前用短超时重新解析设备对象：第一次连接期间卡片若重启，旧对象可能失效。
            # 这里只刷新一次（不是每个重试循环重扫 15s），解析失败则保留旧对象继续尝试。
            find = getattr(BleakScanner, "find_device_by_address", None)
            if find is not None:
                try:
                    refreshed = await find(addr, timeout=min(timeout, 5.0))
                except Exception:
                    refreshed = None
                if refreshed is not None:
                    device = refreshed
    raise RuntimeError("BLE connection failed after retries")   # 不可达；末次尝试已重新抛出

async def read_rssi(client) -> Optional[int]:
    """Best-effort RSSI (dBm) of the *connected* link, or None if unavailable.

    BeeSIM cards stop advertising once connected, so a passive scanner sees
    nothing — we must query the live connection. bleak exposes this on the
    platform backend: `client._backend.get_rssi()` (CoreBluetooth on macOS,
    BlueZ on Linux). Windows has no equivalent, so None there.

    Windows is an OS limitation, not a bug in this client: WinRT's
    BluetoothLEDevice exposes no RSSI for a connected device, and bleak 3.x's
    WinRT backend has no get_rssi() at all. RSSI is only reported by
    BluetoothLEAdvertisementWatcher.Received (RawSignalStrengthInDBm) while
    the device advertises — which BeeSIM stops doing after connecting.
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

