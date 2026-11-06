"""UI strings; protocol identifiers and user profile names stay unchanged."""

# Each entry has Chinese and English; there is no implicit machine translation.
TEXT = {
    "subtitle": ("蓝牙 eUICC 管理工具", "BLE eUICC controller"),
    "scan": ("扫描并连接", "Scan & Connect"),
    "refresh": ("刷新", "Refresh"),
    "download": ("下载 eSIM", "Download eSIM"),
    "enable": ("启用", "Enable"),
    "disable": ("停用", "Disable"),
    "delete": ("删除", "Delete"),
    "rename": ("重命名", "Rename"),
    "txpower": ("蓝牙发射功率", "TX Power"),
    "reset": ("复位芯片", "Reset card"),
    "info": ("芯片信息", "Card info"),
    "info_title": ("芯片信息 EUICCInfo2", "Card info EUICCInfo2"),
    "info_raw_label": ("原始数据（JSON）", "Raw data (JSON)"),
    "info_explain_label": ("字段解读", "Field explanation"),
    "apdu": ("APDU", "APDU"),
    "notifications": ("通知", "Notifications"),
    "send_notification": ("发送通知", "Send notification"),
    "firmware": ("升级固件", "Upgrade firmware"),
    "settings": ("通信设置", "Settings"),
    "language": ("切换语言", "Language"),
    "disconnect": ("断开连接", "Disconnect"),
    "quit": ("退出", "Quit"),
    "cancel": ("取消", "Cancel"),
    "confirm": ("确认", "Confirm"),
    "save": ("保存", "Save"),
    "ok": ("确定", "OK"),
    "connected": ("已连接", "Connected"),
    "disconnected": ("未连接", "Disconnected"),
    "scanning": ("正在扫描…", "Scanning…"),
    "ready": ("按 s 扫描并连接 BeeSIM 芯片。", "Press s to scan and connect your BeeSIM card."),
    "not_connected": ("请先按 s 连接芯片。", "Connect the card with s first."),
    "busy": ("操作进行中，请稍候。", "An operation is in progress. Please wait."),
    "already_connected": ("芯片已连接。", "Already connected."),
    "select_profile": ("请先选中一行配置。", "Select a profile row first."),
    "reading_eid": ("已连接，正在读取 EID…", "Connected. Reading EID…"),
    "reading_profiles": ("正在读取配置列表…", "Reading profiles…"),
    "profile_count": ("共 {count} 个配置。", "{count} profile(s)."),
    "state": ("状态", "State"),
    "name": ("名称", "Name"),
    "provider": ("服务商", "Provider"),
    "class": ("类别", "Class"),
    "on": ("● 已启用", "● ON"),
    "off": ("○ 已停用", "○ OFF"),
    "test": ("测试", "Test"),
    "operational": ("业务", "Operational"),
    "provisioning": ("引导", "Provisioning"),
    "stale": ("数据已过期", "stale"),
    "rssi_unavailable": (
        "Windows 的蓝牙 API 不提供已连接设备的实时信号强度：RSSI 仅存在于广播阶段，"
        "而卡片连接后会停止广播。这是系统限制而非程序故障，此处显示 —；macOS / Linux 可读取。",
        "Windows exposes no RSSI for a connected BLE device: RSSI only appears in "
        "advertisements, and the card stops advertising once connected. This is an OS "
        "limitation, not a bug, so this shows -. macOS/Linux can read the live link."),
    "operation": ("正在{action}…", "{action}…"),
    "done": ("{action}完成。", "{action} completed."),
    "failed": ("{action}失败：{error}", "{action} failed: {error}"),
    "apply_reset": ("操作成功；复位芯片后生效。", "Operation succeeded; reset the card to apply."),
    "delete_question": ("删除配置 {iccid}？此操作无法撤销。", "Delete profile {iccid}? This cannot be undone."),
    "rename_question": ("配置 {iccid} 的新名称", "New nickname for {iccid}"),
    "nickname": ("配置昵称", "Profile nickname"),
    "power_hint": ("0 最低，4 最高；功率越大，范围和耗电越大。", "0 is minimum, 4 maximum; higher power increases range and battery use."),
    "power_min": ("最低", "minimum"),
    "power_max": ("最高", "maximum"),
    "reset_question": ("复位芯片可能暂时中断手机网络，是否继续？", "Resetting may briefly interrupt the phone network. Continue?"),
    "reset_sent": ("复位已发送；若蓝牙断开，请按 s 重新连接。", "Reset sent. If BLE disconnects, reconnect with s."),
    "activation": ("输入 eSIM 激活码", "Enter eSIM activation code"),
    "confirmation_code": ("确认码（不需要时留空）", "Confirmation code (leave blank if not required)"),
    "confirmation_required": ("确认码为必填项", "Confirmation code is required"),
    "proxy_question": ("通过 BeeSIM 官方代理下载？激活码和协议数据会发送给官方服务。", "Download through the official BeeSIM proxy? Activation and protocol data will be sent to that service."),
    "direct_question": ("直接连接 DP+ 服务器下载并安装此配置？", "Download and install this profile directly from the DP+ server?"),
    "Scanning for BeeSIM…": ("正在扫描 BeeSIM…", "Scanning for BeeSIM…"),
    "download_ok": ("配置安装完成，通知已发送；请刷新并按需启用。", "Profile installed and notification sent. Refresh and enable it when needed."),
    "notification_seq": ("通知序号（十六进制，与列表中的 index 一致）", "Notification sequence (hexadecimal index from the list)"),
    "send_question": ("发送通知 {seq} 到其 DP+ 服务器，并在成功后删除？", "Send notification {seq} to its DP+ server and delete it after success?"),
    "no_notifications": ("没有待处理通知。", "No pending notifications."),
    "raw_apdu": ("原始 APDU（十六进制）", "Raw APDU (hexadecimal)"),
    "raw_question": ("原始指令可能修改芯片。确认发送以下 APDU？\n{apdu}", "A raw command may change the card. Send this APDU?\n{apdu}"),
    "store_max_lc": ("STORE DATA 块长（1–255 字节）", "STORE DATA block size (1–255 bytes)"),
    "reply_timeout": ("响应超时（秒）", "Response timeout (seconds)"),
    "channel": ("逻辑通道（1–3）", "Logical channel (1–3)"),
    "delay_counter": ("节流阈值（0 关闭，默认 6）", "Throttle threshold (0 disables, default 6)"),
    "hint_store_max_lc": (
        "STORE DATA 单块数据字节数（Lc）。\n"
        "ES10 命令按此长度分块，逐块以 81 E2 <P1> <块号> <Lc> <数据> 写入卡片；"
        "ISO 7816-4 短 APDU 的 Lc 只有 1 字节，故上限 255。\n"
        "官方 Web 2.3.6 默认 120：调小则分块更多、单条命令更短；调大则命令更少。"
        "仅在出现分块或超时兼容问题时调整。",
        "Data bytes per STORE DATA block (Lc).\n"
        "ES10 commands are split into blocks sent as 81 E2 <P1> <block> <Lc> <data>; "
        "ISO 7816-4 short APDUs use a one-byte Lc, so the maximum is 255.\n"
        "Web 2.3.6 defaults to 120: smaller means more, shorter blocks; larger means fewer "
        "commands. Change only to work around framing or timeout issues."),
    "hint_timeout": (
        "等待卡片经 BLE notify 返回完整 APDU 响应的最长时间（秒）。\n"
        "Web 2.3.6 默认 30 秒。超时后传输层会标记会话失效，必须重新扫描连接，"
        "以免迟到的响应被误当成下一条命令的结果。",
        "Seconds to wait for a complete APDU response over BLE notify.\n"
        "Web 2.3.6 defaults to 30 s. On timeout the transport invalidates the session; "
        "reconnect before sending anything else so a late reply cannot be mistaken for "
        "the next command's response."),
    "hint_channel": (
        "ISO 7816-4 补充逻辑通道号（MANAGE CHANNEL，INS=70）。\n"
        "程序先关闭再打开该通道，随后 SELECT ISD-R；ES10 命令的 CLA = 0x80 | 通道号"
        "（通道 1 即 0x81）。每条通道有独立的应用选择与安全状态。\n"
        "Web 2.3.6 固定用通道 1；仅当卡片拒绝时才试 2 或 3。",
        "ISO 7816-4 supplementary logical channel (MANAGE CHANNEL, INS=70).\n"
        "The app closes then opens this channel and selects ISD-R; ES10 CLA = 0x80 | channel "
        "(0x81 for channel 1). Each channel keeps its own selected application and security state.\n"
        "Web 2.3.6 uses channel 1; try 2 or 3 only if the card rejects it."),
    "hint_delay_counter": (
        "连续发送多少条 APDU 后暂停 1.2 秒，给卡片留出处理时间。\n"
        "官方 Web 2.3.6 应用命令阈值 6；GET RESPONSE(0xC0) 与 0xFE 不计数；"
        "下载配置包与刷固件时程序会临时提高到 20。\n设为 0 关闭节流。",
        "Number of APDUs after which the client pauses 1.2 s to let the card catch up.\n"
        "Web 2.3.6 uses 6 for application commands; GET RESPONSE (0xC0) and 0xFE are not "
        "counted; profile-package and firmware writes temporarily raise it to 20.\n"
        "Set 0 to disable throttling."),
    "settings_saved": ("设置已保存，下次连接时生效。", "Settings saved; applied on the next connection."),
    "settings_invalid": ("请输入有效的块长、超时、通道和节流阈值。", "Enter valid block size, timeout, channel and throttle values."),
    "firmware_path": ("本地固件文本文件路径", "Local firmware text file path"),
    "firmware_question": ("确认刷写 {name}，共 {total} 行？刷写中请保持供电和蓝牙连接。", "Write {name}, {total} rows? Keep power and BLE connected throughout."),
    "firmware_resume": ("发现相同固件进度。是否从第 {row} 行续传？取消则不刷写。", "Matching firmware progress found. Resume at row {row}? Cancel leaves the card unchanged."),
    "firmware_current": ("芯片已经是该固件版本。", "The card already has this firmware version."),
    "firmware_invalid": ("固件文件无效或缺少版本行。", "Invalid firmware file or missing version row."),
    "connect_error": ("连接错误", "Connection error"),
    "transport_timeout": ("等待芯片响应超时，请重新连接。", "Card response timed out; reconnect."),
    "error_open": ("打开通道状态", "OPEN status"),
    "error_select": ("选择 ISD-R 失败", "SELECT ISD-R failed"),
    "error_disconnected": ("蓝牙已断开，请重新连接芯片", "BLE disconnected; reconnect the card"),
    "error_session": ("蓝牙会话不可用，请重新连接芯片", "BLE session unavailable; reconnect the card"),
    "error_not_found": ("未发现 BeeSIM 设备", "No BeeSIM device found"),
    "Reading challenge and EUICCInfo1…": ("正在读取 Challenge 和 EUICCInfo1…", "Reading challenge and EUICCInfo1…"),
    "Authenticating server…": ("正在认证服务器…", "Authenticating server…"),
    "Authenticating client…": ("正在认证客户端…", "Authenticating client…"),
    "Preparing download…": ("正在准备下载…", "Preparing download…"),
    "Downloading profile package…": ("正在下载配置包…", "Downloading profile package…"),
    "Installing profile…": ("正在安装配置…", "Installing profile…"),
    "Sending installation notification…": ("正在发送安装通知…", "Sending installation notification…"),
    "Profile installed; notification delivered.": ("配置已安装，通知已送达。", "Profile installed; notification delivered."),
    "Could not restore TX power; reconnect and set power manually.": ("未能恢复发射功率，请重连后手动设置。", "Could not restore TX power; reconnect and set power manually."),
    "Installation result received; notification pending. Refresh profiles and retry notification; do not repeat download": (
        "已收到安装结果，但通知尚未送达。请刷新配置并重试发送通知，不要重复下载。",
        "Installation result received; notification pending. Refresh profiles and retry notification; do not repeat download"),
}


def translate(key, language="zh", **values):
    pair = TEXT.get(key)
    value = pair[0 if language == "zh" else 1] if pair else key
    return value.format(**values) if values else value


def translate_error(error, language):
    text = str(error)
    if not text and isinstance(error, TimeoutError):
        return translate("transport_timeout", language)
    for original, key in (("SELECT ISD-R failed", "error_select"), ("OPEN status", "error_open"),
                          ("BLE disconnected; reconnect the card", "error_disconnected"),
                          ("BLE session unavailable; reconnect the card", "error_session"),
                          ("No BeeSIM device found", "error_not_found")):
        text = text.replace(original, translate(key, language))
    return translate(text, language)
