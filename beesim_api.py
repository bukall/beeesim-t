"""
对外公共 API：BeeSIMClient —— 供其它程序调用的高层异步客户端。

为什么需要这一层
----------------
beesim.py 是 CLI 入口，内部模块（beesim_transport / beesim_euicc 等）暴露的是
协议级对象。其它程序直接依赖这些对象会绑死内部结构；本模块提供稳定、语义化、
只返回普通 Python 数据的接口，并把生命周期管理集中到一处。

设计约定（维护者 / AI 请先读）
------------------------------
* 单一入口：`from beesim_api import connect_card, BeeSIMClient`。
* 全部方法为 async（底层 bleak 是异步）。不提供同步包装，避免隐藏事件循环。
* 返回值只用 dict / list / str / bool / bytes，不暴露 Euicc、BeeSim、BleakClient。
* 生命周期：推荐 `async with await connect_card() as card:`，退出自动断开 BLE；
  也可 `await card.close()`。断开/超时后必须重新 connect_card()，旧对象不可复用。
* 与 CLI / TUI 完全解耦：本模块不 import textual、不解析 argv、不写 stdout。
* 所有「改变卡片状态」的方法都在 docstring 里标注危险等级，调用方自行确认，
  本模块不会弹窗或二次询问。

典型用法
--------
    import asyncio
    from beesim_api import connect_card

    async def main():
        async with await connect_card() as card:          # 自动扫描 BeeSIM* 设备
            print(await card.eid())                       # EID（32 位十进制）
            for p in await card.profiles():               # 配置列表
                print(p["iccid"], p["profileState"], p.get("profileNickname"))
            print(await card.info_explained("zh"))        # EUICCInfo2 中文解读

    asyncio.run(main())

    # 指定地址、调整通信参数、自定义 RSP 网关：
    # card = await connect_card("12:34:AB:CD:18:22", timeout=45, store_max_lc=120)

分层依赖（本模块位于最上层）
----------------------------
    beesim_tlv        字节 / BER-TLV
      ^ beesim_protocol     常量与协议解析
      ^ beesim_transport    BLE 帧与连接、RSSI
      ^ beesim_euicc        APDU 会话与 ES10 命令
      ^ beesim_download     SGP.22 下载流程
      ^ beesim_web          官方 Web 2.3.6 HTTP API
      ^ beesim_api          本模块（对外）

异常模型
--------
底层可能抛 RuntimeError / ValueError / ConnectionError / TimeoutError / OSError。
常见原因：卡片未在广播、BLE 链路断开或超时、APDU 被卡拒绝、SM-DP+ 拒绝激活码。
APDU 超时后传输层会标记会话失效，必须重新连接（见 beesim_transport 注释）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

from beesim_download import download_profile
from beesim_protocol import describe_euicc_info, parse_activation_code, parse_firmware_text
from beesim_transport import connect, read_rssi
from beesim_tlv import b2h, h2b
from beesim_web import WebAPI

__all__ = ["BeeSIMClient", "connect_card"]

# 静默日志回调：下载/刷固件默认不向 stdout 打进度，调用方可传自己的 log。
_QUIET: Callable[[str], None] = lambda _message: None


async def connect_card(
    address: Optional[str] = None,
    *,
    debug: bool = False,
    timeout: float = 30.0,
    store_max_lc: int = 120,
    channel: int = 1,
    delay_over_counter: int = 6,
    gateway: Optional[Any] = None,
) -> "BeeSIMClient":
    """连接 BeeSIM 卡并返回一个高层客户端。

    参数
    ----
    address
        BLE MAC/UUID。None 表示按名称前缀 ``BeeSIM`` 扫描 15 秒。
    debug
        True 时把全部 APDU 往来打印到 stderr（排查协议问题用）。
    timeout
        等待单条 APDU 响应的秒数（Web 2.3.6 默认 30）。超时后必须重连。
    store_max_lc
        单条 STORE DATA 的数据字节数，1..255，默认 120。
    channel
        ISO 7816-4 逻辑通道 1..3，默认 1。
    delay_over_counter
        连续多少条 APDU 后暂停 1.2 秒，默认 6；0 关闭节流。
    gateway
        可选 ES9+ 网关对象（需实现 async execute(action, smdp, protocol, fields)）。
        None 时使用官方 Web 代理 WebAPI；也可传 beesim_web.DirectRSP()。

    返回
    ----
    BeeSIMClient，已连接。调用方负责 ``await close()`` 或用 async with。

    说明
    ----
    本函数只建立 BLE 会话，不会读取 EID/配置，也不会改动卡片状态。
    """
    ble_client, sim, euicc = await connect(
        address,
        debug=debug,
        timeout=timeout,
        store_max_lc=store_max_lc,
        channel=channel,
        delay_over_counter=delay_over_counter,
    )
    return BeeSIMClient(ble_client, sim, euicc, gateway=gateway)


class BeeSIMClient:
    """一张已连接 BeeSIM eUICC 卡的高层异步门面。

    不要直接实例化，使用 :func:`connect_card` 或 ``await BeeSIMClient.connect()``。
    内部持有 (BleakClient, BeeSim, Euicc)，但对调用方只暴露语义化方法。
    非线程安全：同一客户端的 BLE 命令已由传输层串行化，跨线程共享仍不推荐。
    """

    def __init__(self, ble_client: Any, sim: Any, euicc: Any, *, gateway: Optional[Any] = None) -> None:
        """内部构造器；参数含义见 connect_card。外部请使用工厂函数。"""
        self._ble = ble_client
        self._sim = sim
        self._euicc = euicc
        self._gateway = gateway
        self._closed = False

    @classmethod
    async def connect(cls, address: Optional[str] = None, **kwargs: Any) -> "BeeSIMClient":
        """等价于 :func:`connect_card`，便于写成 ``await BeeSIMClient.connect()``。"""
        return await connect_card(address, **kwargs)

    # --- 生命周期 -----------------------------------------------------------
    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("BeeSIM client is closed; call connect_card() again")

    @property
    def closed(self) -> bool:
        """连接是否已关闭。"""
        return self._closed

    @property
    def address(self) -> str:
        """当前连接的 BLE 地址。"""
        return str(getattr(self._ble, "address", ""))

    @property
    def protocol(self) -> str:
        """当前协商出的 GSMA RSP 协议版本字符串（如 gsma/rsp/v2.2.2）。"""
        return str(self._sim.protocol)

    async def close(self) -> None:
        """断开 BLE 连接。重复调用安全；断开后不可再复用本对象。"""
        if self._closed:
            return
        self._closed = True
        await self._ble.disconnect()

    async def __aenter__(self) -> "BeeSIMClient":
        self._ensure_open()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    # --- 只读查询 -----------------------------------------------------------
    async def eid(self) -> str:
        """读取 EID（eUICC 硬件唯一标识，32 位十进制字符串）。"""
        self._ensure_open()
        return str(await self._sim.get_eid())

    async def profiles(self, selector: Optional[str] = None) -> list[dict]:
        """读取配置列表。

        selector 为 None 时读取全部字段；传入十六进制标签列表（如
        ``"5C075A9F7090919295"``）或 ISD-P AID 时按卡片支持的方式过滤。
        返回 dict 列表，常见键：iccid / isdpAid / profileState(ON|OFF) /
        profileNickname / serviceProviderName / profileName / profileClass。
        """
        self._ensure_open()
        return list(await self._sim.get_profiles(selector))

    async def euicc_info1(self) -> dict:
        """读取 EUICCInfo1（svn 与 CI 公钥列表，含 raw 十六进制）。"""
        self._ensure_open()
        return dict(await self._sim.get_euicc_info1())

    async def euicc_info2(self) -> dict:
        """读取 EUICCInfo2（固件版本、卡资源、能力位图等，含 raw）。"""
        self._ensure_open()
        return dict(await self._sim.get_euicc_info2())

    async def info(self) -> dict:
        """``euicc_info2()`` 的别名，对应 CLI 的 ``info`` / TUI 的 ``i``。"""
        return await self.euicc_info2()

    async def info_explained(self, language: str = "zh") -> str:
        """返回 EUICCInfo2 的人类可读解读（zh 中文 / 其它为英文），JSON 另行取 info()。"""
        return describe_euicc_info(await self.info(), language, "EUICCInfo2")

    async def raw_apdu(self, hex_command: str) -> str:
        """发送一条原始 APDU（十六进制字符串），返回响应的十六进制字符串。

        ⚠ 高级/危险：原始指令可能修改卡片状态。发送后内部会话会标记为未初始化，
        下一条 ES10 命令会重新走 CLOSE/OPEN/SELECT 流程。
        """
        self._ensure_open()
        try:
            response = await self._euicc.send_command(h2b(hex_command), reinit_on_6881=False)
        finally:
            self._euicc.inited = False
        return b2h(response)

    async def rssi(self) -> Optional[int]:
        """尽力读取已连接链路的 RSSI(dBm)；Windows 恒返回 None（平台限制）。"""
        self._ensure_open()
        return await read_rssi(self._ble)

    # --- 配置管理（会改变卡片状态）------------------------------------------
    async def enable(self, iccid: str, *, refresh: bool = True) -> bool:
        """启用配置。⚠ 会改变卡片状态，可能使手机短暂重新搜网。

        refresh=True（默认，与 CLI 一致）在成功后发送软复位让配置生效。
        返回 True 表示成功；卡片返回「已启用」(02) 也视为成功。
        """
        self._ensure_open()
        ok = bool(await self._sim.enable_profile(iccid))
        if ok and refresh:
            await self._euicc.reset()
        return ok

    async def disable(self, iccid: str, *, refresh: bool = True) -> bool:
        """停用配置。⚠ 会改变卡片状态；refresh 语义同 enable()。"""
        self._ensure_open()
        ok = bool(await self._sim.disable_profile(iccid))
        if ok and refresh:
            await self._euicc.reset()
        return ok

    async def delete(self, iccid: str) -> bool:
        """删除配置（不可逆）。⚠⚠ 高危：调用方必须先自行核对 ICCID。

        卡片要求目标处于停用状态，已启用的配置会返回 wrong-state(02)。
        删除会产生一条 DELETE 通知；按本项目策略，该通知发送后仍保留在卡上。
        """
        self._ensure_open()
        return bool(await self._sim.delete_profile(iccid))

    async def rename(self, iccid: str, nickname: str) -> bool:
        """修改配置昵称（UTF-8）。⚠ 会改变卡片状态，但可逆。"""
        self._ensure_open()
        return bool(await self._sim.set_nickname(iccid, nickname))

    async def reset(self) -> None:
        """软复位 eUICC（A0 3F），让手机重新识别配置。⚠ 会短暂中断网络。"""
        self._ensure_open()
        await self._euicc.reset()

    async def set_tx_power(self, level: int) -> None:
        """设置 BLE 发射功率 0..4。⚠ 0=最小、4=最大；改错可能导致连不上。"""
        self._ensure_open()
        await self._euicc.set_tx_power(level)

    # --- 通知 ---------------------------------------------------------------
    async def notifications(self, operation: Optional[str] = None,
                            *, decoded: bool = True) -> list[dict] | bytes:
        """列出待发送通知。

        operation 可为 INSTALL / ENABLE / DISABLE / DELETE，None 表示全部。
        decoded=True 返回 dict 列表（index / profileManagementOperation /
        notificationAddress / iccid）；False 返回原始响应字节。
        """
        self._ensure_open()
        result = await self._sim.list_notifications(operation, decoded=decoded)
        return list(result) if decoded else bytes(result)

    async def retrieve_notification(self, seq: Optional[str] = None) -> bytes:
        """检索通知原始 TLV；seq 为十六进制序号，None 表示全部。"""
        self._ensure_open()
        return bytes(await self._sim.retrieve_notification(seq))

    async def send_notification(self, seq: str, gateway: Optional[Any] = None) -> dict:
        """把通知发送给其 SM-DP+ 服务器。⚠ 会产生真实外部 HTTPS 请求。

        成功后：INSTALL/ENABLE/DISABLE 通知会从卡上删除；DELETE（删卡）通知
        按本项目策略**保留**在卡上（与官方 Web 有意不同）。
        发送失败时通知保留，可稍后重试，不要重复下载配置。
        """
        self._ensure_open()
        return dict(await self._sim.send_notification(seq, gateway or self._gateway))

    async def remove_notification(self, seq: str) -> bool:
        """直接从卡上丢弃一条通知（不发送给服务器）。⚠ 不可恢复。"""
        self._ensure_open()
        return bool(await self._sim.remove_notification(seq))

    # --- 固件 ---------------------------------------------------------------
    async def firmware_status(self) -> dict:
        """读取固件升级进度（crc / totalRows / currentRow）。只读。"""
        self._ensure_open()
        return dict(await self._euicc.check_upgrading())

    @staticmethod
    async def firmware_versions() -> dict:
        """查询官方固件版本列表（纯 HTTP，不需要 BLE 连接）。"""
        return dict(await WebAPI().firmware_versions())

    async def firmware_write(self, path: str, *, resume: bool = False,
                             log: Optional[Callable[[str], None]] = None) -> dict:
        """刷写本地厂商固件文本。⚠⚠⚠ 极高危：可能使卡片不可用。

        调用方必须自行确认；本方法不做二次询问。文件需含 F0 行与末尾 F2 行，
        并由倒数第二行提供 CRC。resume=True 时仅在 CRC 与总行数匹配后续传。
        """
        self._ensure_open()
        firmware = parse_firmware_text(Path(path).expanduser().read_text())
        progress = await self._euicc.check_upgrading()
        rows = firmware["rows"]
        start = 1
        if resume:
            if progress["crc"] != firmware["crc"] or progress["totalRows"] != len(rows):
                raise ValueError("Firmware progress does not match this file")
            start = progress["currentRow"] + 1
        if start > len(rows):
            return {"status": "already-complete", "totalRows": len(rows)}
        pending = rows[start - 1:]
        await self._sim.download_firmware(pending, len(rows), start, log or _QUIET)
        return {"status": "written", "start": start, "rows": len(pending)}

    # --- 下载安装 -----------------------------------------------------------
    async def download(self, activation_code: str, *, confirm_code: Optional[str] = None,
                       gateway: Optional[Any] = None,
                       log: Optional[Callable[[str], None]] = None) -> dict:
        """按 LPA 激活码下载并安装 eSIM 配置。⚠ 会写卡并产生外部 HTTPS 请求。

        activation_code 形如 ``LPA:1$<smdp>$<matchingId>``；若激活码要求确认码
        而未提供，会抛 ValueError。默认走官方代理，可传 gateway 覆盖。
        安装期间 TX 功率临时提升到 4，成功或失败都会尝试恢复到 1。
        新配置默认处于停用状态，需要时再调用 enable()。
        """
        self._ensure_open()
        smdp, matching_id, cc_required = parse_activation_code(activation_code)
        if cc_required and not confirm_code:
            raise ValueError("Confirmation code required for this activation code")
        return dict(await download_profile(
            self._sim, self._euicc, smdp, matching_id, confirm_code,
            log=log or _QUIET, gateway=gateway or self._gateway,
        ))
