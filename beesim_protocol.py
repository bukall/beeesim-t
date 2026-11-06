"""
eUICC 协议常量与「原始响应 -> 可读结构」解析层。

职责
----
* 保存官方 BeeSIM Web 2.3.6 的常量与通信参数默认值
  （权威记录见 web-api-reference.json，语义来自 ISO 7816-4 / GSMA SGP.22）
* 解析 ES10 响应：ProfileInfo、EUICCInfo1/2、通知元数据、安装结果、Profile 元数据
* 解析输入：LPA 激活码、厂商固件文本、Bound Profile Package 分块
* 生成 EUICCInfo 的中/英文人类可读解读（describe_euicc_info）

依赖方向：仅依赖 beesim_tlv；不 import bleak / textual / beesim_web / CLI / TUI。

协议要点
--------
* ES10 命令是 BER-TLV，装在 STORE DATA(81 E2) 里；响应用 GET RESPONSE(81 C0) 拉回。
* ICCID 在卡上以半字节交换的 BCD 存放（tag 5A），读出后 swap_nibbles + 去尾部 F。
* 通知操作 tag 81 是 BIT STRING：0780=INSTALL / 0640=ENABLE /
  0520=DISABLE / 0410=DELETE（与官方 JS 的 J.toBytes / J.toLabel 一致）。
* describe_euicc_info 的字段说明依据 SGP.22 EUICCInfo2 ASN.1，不是猜测；
  位图字段（uiccCapability / rspCapability）按原始十六进制输出，未逐位解码。

与官方 JS 的对应（对照 src/*.js）
--------------------------------
  parse_tlv / find_tag        -> K / be / ye
  _parse_profile              -> ze / Re
  _parse_euicc_info           -> Ee / De
  _notification_metadata      -> Q / Oe
  parse_installation_result   -> je
  _bpp_to_blocks              -> Be.toBlocks
"""

from __future__ import annotations

import base64
import re
from typing import Any, List, Optional, Tuple

from beesim_tlv import (
    b2h, der_len, find_tag, h2b, parse_tlv, serialize_tlv,
    swap_nibbles, _int_bytes, _tlv_to_debug,
)

# --------------------------------------------------------------------------- #
# Constants (verified from the web bundle)
# --------------------------------------------------------------------------- #
SERVICE_UUID = "0000ae30-0000-1000-8000-00805f9b34fb"
NAME_PREFIX = "BeeSIM"

# GSMA ISD-R AID selected on the logical channel (A4 04 00) before any ES10 cmd.
ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")

# --------------------------------------------------------------------------- #
# Communication settings shown in the TUI "Settings" dialog (and CLI flags).
# Defaults come from the official BeeSIM Web 2.3.6 bundle, recorded in
# web-api-reference.json; semantics follow ISO 7816-4 and GSMA SGP.22.
#
# store_max_lc = 120
#   Data bytes carried by one STORE DATA (INS E2) block. _store_bytes() splits
#   an ES10 command TLV into blocks of this size and sends each as
#   81 E2 <P1=0x11/0x91> <block> <Lc> <data>. ISO 7816-4 short APDUs encode Lc
#   in one byte, hence the 1..255 range. Web 2.3.6 uses 120. This is unrelated
#   to the 18-byte BLE packet grouping (GROUP_PAYLOAD). Smaller means more but
#   shorter blocks; larger means fewer commands.
#
# timeout = 30 s
#   BeeSimTransport.send() waits at most this long for the card's notifications
#   to reassemble one full APDU response. Web 2.3.6 uses 30000 ms. A timeout
#   marks the transport closed: a late reply must never be mistaken for the
#   next command's response, so reconnect before issuing further commands.
#
# channel = 1
#   ISO 7816-4 supplementary logical channel opened with MANAGE CHANNEL
#   (INS 70; 00 70 80 <ch> 00 closes, 00 70 00 <ch> 00 opens) before SELECT
#   ISD-R. Each channel keeps its own selected application and security state.
#   ES10 CLA = 0x80 | channel (0x81 for channel 1), see Euicc._store_bytes.
#   Web 2.3.6 fixes channel 1; this client allows 1..3 for compatibility.
#
# delay_over_counter = 6
#   Throttle: after this many APDUs (GET RESPONSE 0xC0 and 0xFE are excluded)
#   the client sleeps 1.2 s so the card can catch up, then resets the counter.
#   Web 2.3.6 uses 6 for application commands and 20 for BPP/firmware
#   writes; load_bound_profile_package()/download_firmware() temporarily set
#   the latter. 0 disables throttling.
# --------------------------------------------------------------------------- #
STORE_MAX_LC = 120          # Web 2.3.6 default; distinct from 18-byte BLE groups
GROUP_PAYLOAD = 18          # bytes of APDU per BLE packet          (groupValue)
LOGICAL_CHANNEL = 1         # fixed logical channel                 (pe.channel)


# --------------------------------------------------------------------------- #

# Profile-info parsing (port of Re/ze)
# --------------------------------------------------------------------------- #

def _parse_profile(e3: dict) -> dict:
    # Values are heterogeneous: strings, hex strings, dicts (decoded TLV trees).
    out: dict[str, Any] = {}
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
        elif t == "9F24" and isinstance(v, bytes) and v:
            # SGP.22 ProfileInfo.enabledOnEsimPort（多 eSIM 端口卡标识启用端口）
            out["enabledOnEsimPort"] = int.from_bytes(v, "big")
        elif t == "9F25" and isinstance(v, bytes) and v:
            # SGP.22 ProfileInfo.profileSize：卡报告的该配置近似大小（字节）。
            # 由 EUICCInfo2 rspCapability 的 profileSizeInProfilesInfoSupport
            # (bit 14) 控制；不支持的卡不带此字段。官方/NekokoLPA2 据此显示
            # 每张配置的大小，并可累加出近似总容量。
            out["profileSize"] = int.from_bytes(v, "big")
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


# Human-readable explanation of EUICCInfo1/EUICCInfo2. Field names and meanings
# follow GSMA SGP.22 (EUICCInfo2 ASN.1) and the parser above, not guesswork.
# Entries: (zh label, en label, zh description, en description).
_EUICC_INFO_FIELDS = {
    "profileVersion": (
        "基础配置包版本", "Base profile package version",
        "卡片支持的基础 eSIM 配置包（Profile Package）版本，决定能装载哪种格式的配置文件。",
        "Base eSIM Profile Package version the eUICC supports; it decides which profile format can be loaded."),
    "svn": (
        "SGP.22 规范版本", "SGP.22 specification version",
        "卡片实现的 GSMA SGP.22 版本；程序据此协商 ES9+ 的 X-Admin-Protocol（gsma/rsp/v<svn>）。",
        "GSMA SGP.22 version implemented by the card; the client negotiates the ES9+ X-Admin-Protocol from it."),
    "euiccFirmwareVer": (
        "芯片固件版本", "eUICC firmware version",
        "eUICC 芯片自身的固件版本，与 BeeSIM Web 网页版本号不是一回事。",
        "Firmware version of the eUICC chip itself, not the BeeSIM Web app version."),
    "extCardResource": (
        "卡内资源", "Card resources",
        "按 ETSI TS 102 226 的扩展卡资源信息：可安装的配置实例数、空闲非易失存储（字节）、空闲易失内存（字节）。",
        "Extended card resource per ETSI TS 102 226: available profile instances, free non-volatile and volatile memory (bytes)."),
    "uiccCapability": (
        "UICC 能力", "UICC capability",
        "SGP.22 UICCCapability 位图（USIM/ISIM/CSIM、Java Card 等）；本程序按原始十六进制输出，未逐位解码。",
        "SGP.22 UICCCapability bitmap (USIM/ISIM/CSIM, Java Card, ...); shown as raw hex, not decoded bit by bit."),
    "ts102241Version": (
        "TS 102.241 版本", "TS 102.241 version",
        "ETSI TS 102 241（UICC Java Card 平台）版本；SGP.22 v2.1 起由 javacardVersion 改名而来。",
        "ETSI TS 102 241 (UICC Java Card platform) version; renamed from javacardVersion in SGP.22 v2.1."),
    "globalplatformVersion": (
        "GlobalPlatform 版本", "GlobalPlatform version",
        "GlobalPlatform 卡管理规范版本；ISD-R 的逻辑通道与应用选择基于该规范。",
        "GlobalPlatform card management version; ISD-R logical channels and application selection build on it."),
    "rspCapability": (
        "RSP 能力", "RSP capability",
        "SGP.22 EuiccRspCapability 位图（如 additionalProfile、testProfileSupport）；本程序按原始十六进制输出。",
        "SGP.22 EuiccRspCapability bitmap (e.g. additionalProfile, testProfileSupport); shown as raw hex."),
    "euiccCategory": (
        "eUICC 类别", "eUICC category",
        "SGP.22 定义 other/basicEuicc/mediumEuicc/contactlessEuicc，已标记为弃用；部分卡不提供。",
        "SGP.22 other/basicEuicc/mediumEuicc/contactlessEuicc; deprecated and often absent."),
    "forbiddenProfilePolicyRules": (
        "禁用的配置策略规则", "Forbidden profile policy rules",
        "卡片声明不允许生效的 Profile Policy Rules（PPR）标识。",
        "Profile Policy Rules (PPR) identifiers the card declares as not allowed."),
    "ppVersion": (
        "保护轮廓版本", "Protection Profile version",
        "SGP.22 ppVersion：芯片安全认证所依据的通用准则（CC）保护轮廓版本。",
        "SGP.22 ppVersion: Common Criteria Protection Profile version used for the chip's security certification."),
    "sasAcreditationNumber": (
        "SAS 认证编号", "SAS accreditation number",
        "GSMA SAS 安全认证编号（SGP.22 原字段拼写即 Acreditation，标准正确拼写为 Accreditation）。",
        "GSMA SAS security accreditation number (the SGP.22 field name spells it 'Acreditation')."),
    "certificationDataObject": (
        "认证数据对象", "Certification data object",
        "认证附加数据，如平台标签（Platform_Label）与 DLOA 发现服务 URL。",
        "Certification data such as the Platform_Label and the DLOA registrar discovery URL."),
    "euiccCiPKIdListForVerification": (
        "验签用 CI 公钥列表", "CI public key IDs for verification",
        "卡片信任的 eSIM CA 根证书公钥标识，用于校验 SM-DP+ 证书链的签名。",
        "eSIM CA root public key IDs trusted by the card to verify the SM-DP+ certificate chain."),
    "euiccCiPKIdListForSigning": (
        "签名用 CI 公钥列表", "CI public key IDs for signing",
        "卡片信任的 eSIM CA 根证书公钥标识，用于生成可被服务器验证的签名证书链。",
        "eSIM CA root public key IDs trusted by the card when creating a certificate chain the server can verify."),
}

_CARD_RESOURCE_LABELS = {
    "installedApplication": ("已安装应用数", "installed applications"),
    "freeNonVolatileMemory": ("空闲非易失存储(字节)", "free non-volatile memory (bytes)"),
    "freeVolatileMemory": ("空闲易失内存(字节)", "free volatile memory (bytes)"),
}


def _format_info_value(value, limit=300) -> str:
    if isinstance(value, dict):
        text = ", ".join(f"{k}={_format_info_value(v, 80)}" for k, v in value.items())
    elif isinstance(value, list):
        text = ", ".join(_format_info_value(v, 80) for v in value)
    else:
        text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


def describe_euicc_info(info: dict, language: str = "zh", title: Optional[str] = None) -> str:
    """Explain EUICCInfo1/EUICCInfo2 in Chinese (or English) alongside the raw JSON."""
    zh = language != "en"
    heading = title or ("芯片信息" if zh else "eUICC information")
    lines = [f"【{heading} · {'中文解读' if zh else 'explained'}】"]
    for key, value in info.items():
        if key == "raw":
            continue
        meta = _EUICC_INFO_FIELDS.get(key)
        if meta is None:
            note = "未收录字段，按原值显示" if zh else "unmapped field, shown as-is"
            lines.append(f"  {key}: {_format_info_value(value)}  ({note})")
            continue
        name, desc = (meta[0], meta[2]) if zh else (meta[1], meta[3])
        if key == "extCardResource" and isinstance(value, dict):
            parts = []
            for sub, v in value.items():
                label = _CARD_RESOURCE_LABELS.get(sub, (sub, sub))[0 if zh else 1]
                text = _format_info_value(v, 80)
                # 官方 Web 把空闲内存按 bytes/1024 显示为 KB；解读中同时给出。
                if sub in ("freeNonVolatileMemory", "freeVolatileMemory") and isinstance(v, int):
                    text = (f"{text} 字节 = {format_capacity_kb(v)}" if zh
                            else f"{text} bytes = {format_capacity_kb(v)}")
                parts.append(f"{label}={text}")
            shown = "; ".join(parts)
        else:
            shown = _format_info_value(value)
        lines.append(f"  {name} ({key}): {shown}")
        lines.append(f"      {desc}")
    if "raw" in info:
        lines.append("  " + ("raw: 卡片返回的原始 BER-TLV 十六进制，供协议排错使用。"
                            if zh else "raw: original BER-TLV response in hex, for protocol debugging."))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 剩余可用容量与近似总容量
#
# 剩余容量（官方 Web「查看剩余可用容量」，本地 src/ JS 函数 S / toExtCardResource）：
#   await GetEUICCInfo2() -> extCardResource.freeNonVolatileMemory
#   -> (bytes / 1024).toFixed(2) + "KB"
#
# 每张配置的近似大小（与 NekokoLPA2 一致）：
#   GetProfilesInfo 响应里每个 ProfileInfo(E3) 的 tag 9F25 profileSize（字节），
#   由 EUICCInfo2.rspCapability 的 profileSizeInProfilesInfoSupport (bit 14) 控制；
#   不支持的卡不带该字段，此时单卡大小为 None。
#
# 近似总容量：sum(每张配置的 profileSize) + freeNonVolatileMemory。
# 协议（ETSI TS 102 226 §8.2.1.7.2 / SGP.22）**没有**总容量字段，所以上式只是
# 估算：不含系统/文件系统开销，且只统计已报告 profileSize 的配置。程序绝不
# 引入「标称总容量」这类外部猜测值（已按需求移除）。
# --------------------------------------------------------------------------- #
def format_capacity_kb(num_bytes: int) -> str:
    """按官方 Web 的格式把字节数转为 KB 字符串：bytes/1024 保留两位 + 'KB'。

    注意：官方 JS 用的虽是 1024 进制，但单位写作 KB（不是 KiB），这里刻意沿用，
    以便与网页显示完全一致，例如 21217 字节 -> ``20.72KB``。
    """
    return f"{num_bytes / 1024:.2f}KB"


def capacity_data(info: dict, profiles: Optional[List[dict]] = None) -> dict:
    """从 EUICCInfo2 + 配置列表计算容量数据（剩余、逐卡大小、近似总容量）。

    参数
    ----
    info
        :func:`_parse_euicc_info` / ``BeeSim.get_euicc_info2()`` 的返回值。
    profiles
        :func:`_parse_profile` / ``BeeSim.get_profiles()`` 的返回值列表；
        传 None 或空列表时不统计逐卡大小，也就无法给出近似总容量。

    返回
    ----
    dict：
      freeBytes / freeKB                 剩余可用容量（官方显示值）
      freeVolatileBytes / freeVolatileKB 空闲易失内存
      installedApplication               已安装应用数
      profiles                           逐卡 {iccid, nickname, profileSize, profileSizeKB}
      profilesWithSize                   报告了 profileSize 的配置数量
      profileSizeSource                  单卡大小的字段来源
      installedBytes / installedKB       已安装配置占用合计（仅含报告了大小的）
      totalBytesApprox / totalKBApprox   近似总容量 = installed + free
      usedPercentApprox                  近似已用占比（%）
      source                             卡字段来源说明
    未能统计时（无任何 profileSize），installed/total/used 相关字段为 None。
    """
    resource = info.get("extCardResource")
    if not isinstance(resource, dict):
        raise ValueError("extCardResource missing from EUICCInfo2")
    free = int(resource.get("freeNonVolatileMemory", 0))
    volatile = int(resource.get("freeVolatileMemory", 0))
    apps = int(resource.get("installedApplication", 0))
    items: list[dict[str, Any]] = []
    installed = 0
    sized = 0
    for profile in profiles or []:
        size = profile.get("profileSize")
        known = size if isinstance(size, int) else None
        items.append({
            "iccid": profile.get("iccid"),
            "nickname": profile.get("profileNickname") or profile.get("profileName") or "",
            "profileSize": known,
            "profileSizeKB": format_capacity_kb(known) if known is not None else None,
        })
        if known is not None:
            installed += known
            sized += 1
    data: dict[str, Any] = {
        "freeBytes": free,
        "freeKB": format_capacity_kb(free),
        "freeVolatileBytes": volatile,
        "freeVolatileKB": format_capacity_kb(volatile),
        "installedApplication": apps,
        "source": "EUICCInfo2.extCardResource (ETSI TS 102 226 FF21)",
        "profiles": items,
        "profilesWithSize": sized,
        "profileSizeSource": "ProfileInfo.profileSize (tag 9F25, SGP.22)",
        "installedBytes": None,
        "installedKB": None,
        "totalBytesApprox": None,
        "totalKBApprox": None,
        "usedPercentApprox": None,
    }
    if sized:
        total_approx = installed + free
        data.update({
            "installedBytes": installed,
            "installedKB": format_capacity_kb(installed),
            "totalBytesApprox": total_approx,
            "totalKBApprox": format_capacity_kb(total_approx),
            "usedPercentApprox": round(installed * 100 / total_approx, 1) if total_approx else None,
        })
    return data


def describe_capacity(data: dict, language: str = "zh") -> str:
    """把 :func:`capacity_data` 的结果转成中/英文可读说明。"""
    zh = language != "en"
    lines = [f"【{'容量' if zh else 'Capacity'}】"]
    if zh:
        lines.append(f"  剩余可用容量: {data['freeKB']} ({data['freeBytes']} 字节)")
        lines.append(f"  空闲易失内存: {data['freeVolatileKB']} ({data['freeVolatileBytes']} 字节)")
        lines.append(f"  已安装应用数: {data['installedApplication']}")
    else:
        lines.append(f"  Remaining: {data['freeKB']} ({data['freeBytes']} bytes)")
        lines.append(f"  Free volatile memory: {data['freeVolatileKB']} ({data['freeVolatileBytes']} bytes)")
        lines.append(f"  Installed applications: {data['installedApplication']}")
    if data["profiles"]:
        lines.append("  " + ("各配置近似大小（来自 profileSize）:" if zh
                            else "Approximate size per profile (from profileSize):"))
        for item in data["profiles"]:
            label = item["nickname"] or item["iccid"] or "?"
            if item["profileSize"] is not None:
                suffix = (f"{item['profileSizeKB']} ({item['profileSize']} 字节)" if zh
                          else f"{item['profileSizeKB']} ({item['profileSize']} bytes)")
            else:
                suffix = "未报告" if zh else "not reported"
            lines.append(f"    {label}: {suffix}")
    if data["totalBytesApprox"] is not None:
        if zh:
            lines.append(f"  已安装合计: {data['installedKB']} ({data['installedBytes']} 字节)")
            lines.append(f"  近似总容量: {data['totalKBApprox']} ({data['totalBytesApprox']} 字节) = 已安装 + 剩余")
            lines.append(f"  近似已用占比: {data['usedPercentApprox']}%")
        else:
            lines.append(f"  Installed total: {data['installedKB']} ({data['installedBytes']} bytes)")
            lines.append(f"  Approx. total capacity: {data['totalKBApprox']} ({data['totalBytesApprox']} bytes) = installed + free")
            lines.append(f"  Approx. used: {data['usedPercentApprox']}%")
    else:
        lines.append("  " + ("近似总容量: 无法计算（卡未报告 profileSize）" if zh
                            else "Approx. total capacity: unavailable (card reports no profileSize)"))
    lines.append("  " + ("说明: 卡片协议不含总容量字段；近似总容量 = 各配置 profileSize 之和 + 剩余可用容量，不含系统开销。"
                        if zh else "Note: the protocol has no total-capacity field; the approximation sums profileSize plus free memory and excludes system overhead."))
    return "\n".join(lines)


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

