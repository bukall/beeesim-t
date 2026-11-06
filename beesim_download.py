"""
SGP.22 eSIM 下载流程（卡侧 ES10b 与服务器侧 ES9+ 交错执行）。

八步（与官方 Web 2.3.6 一致）
-----------------------------
  [1] ES10b GetEUICCChallenge + GetEUICCInfo1          卡侧（BLE）
  [2] ES9+  initiateAuthentication                      服务器侧
  [3] ES10b AuthenticateServer (BF38)                  卡侧
  [4] ES9+  authenticateClient                         服务器侧
  [5] ES10b PrepareDownload (BF21)                     卡侧
  [6] ES9+  getBoundProfilePackage                     服务器侧
  [7] ES10b LoadBoundProfilePackage（BPP 分块写入）    卡侧
  [8] ES9+  handleNotification，然后删除安装通知

重要约定（维护者 / AI 请先读）
------------------------------
* 下载期间 TX 功率提升到 4；**无论成功或失败**都在 finally 恢复到 1
  （官方 v2.1.4 JS 只提升不恢复，这是有意的安全差异，见 web-api-reference.json）。
* 通知发送失败时抛错且保留卡上通知，不要重复下载；刷新后重试 notification-send。
* 默认走官方 HTTPS 代理；DirectRSP 为可选直连模式。
* 本模块只在函数内部 import beesim_web，避免离线测试被迫加载 HTTP 栈。
"""

from __future__ import annotations

import base64
from typing import Optional, TYPE_CHECKING

from beesim_protocol import _profile_meta, parse_installation_result
from beesim_tlv import h2b

if TYPE_CHECKING:
    from beesim_euicc import BeeSim, Euicc

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


