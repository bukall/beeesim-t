# beeesim-t

用蓝牙管理 **BeeSIM eUICC 卡（eSIM）** 的 Python 工具 —— 命令行、中英双语终端界面、
以及可编程调用的异步 API。配置管理完全走蓝牙；只有**下载新 eSIM** 时才需要联网
（连运营商的 SM-DP+，默认走 BeeSIM 官方代理）。

A Python BLE controller for **BeeSIM eUICC cards** (eSIM) — CLI, bilingual
terminal UI, and a programmable async API. Profile management runs entirely over
Bluetooth; downloading a new eSIM is the only thing that also talks HTTPS (to the
operator's SM-DP+, through the official BeeSIM proxy by default).

本项目基于 [cyyself/beeesim-api](https://github.com/cyyself/beeesim-api) 二次开发，
保留其 BLE/eUICC 协议逆向成果与 Git 历史；实现对齐官方 **BeeSIM Web v2.3.6**，
适配 **1.3.6 固件**。

> ⚠️ 这张卡的 BLE 管理接口**没有任何认证**：任何在射频范围内的设备都能改写你的 eSIM。
> 使用前请先读 [安全警告](#️-security-warning)。

## Features

- 配置：列出 / 启用 / 停用 / 删除 / 改名（实时 ON/OFF 状态）
- 芯片信息（EID、EUICCInfo1/2），附中/英字段逐项解读
- 通知：列出 / 检索 / 发送到 SM-DP+ / 删除
- 下载 eSIM（GSMA SGP.22 完整八步），支持确认码
- 固件：状态 / 版本列表 / 本地文本刷写（高危）
- 容量：剩余容量（与官方网页同款换算）、逐卡 profileSize、近似总容量
- 中英双语 TUI、CLI、以及 `beesim_api.BeeSIMClient` 编程接口
- 通信参数可调（块长 / 超时 / 逻辑通道 / 节流）

## Architecture

核心按职责分层，每层只依赖下层；每个模块都有中文 docstring，说明职责、数据流、
协议不变量，以及与官方 JS 函数的对应关系。

| 模块 | 职责 |
|---|---|
| `beesim_tlv.py` | 字节 / BER-TLV 编解码（纯函数，无 I/O） |
| `beesim_protocol.py` | 常量、ES10 响应解析、LPA/固件/BPP 解析、EUICCInfo 与容量说明 |
| `beesim_transport.py` | BLE GATT 连接、18 字节分组帧、`connect()` / `read_rssi()` |
| `beesim_euicc.py` | `Euicc`（APDU 会话）与 `BeeSim`（ES10 命令集） |
| `beesim_download.py` | SGP.22 下载流程（ES10b + ES9+） |
| `beesim_api.py` | **对外接口**：`BeeSIMClient` / `connect_card`（集成请从这里开始） |
| `beesim.py` | CLI 入口（argparse + 分发） |
| `beesim_web.py` | BeeSIM Web 2.3.6 HTTP API、签名、可选直连 RSP |
| `beesim_tui.py`, `beesim_i18n.py` | 双语 Textual 界面与文案 |

`assets/` 与 `src/` 是官方网页（v2.1.4）的历史快照，作为逆向依据保留，**不参与运行**；
`web-api-reference.json` 记录 v2.3.6 的源哈希、接口合约与有意差异。

## Install

```bash
python3 -m venv .venv          # Python 3.11+
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install --only-binary=:all: -r requirements.txt   # bleak, textual, cryptography
```

需要一台有蓝牙适配器、且系统已授权 BLE 的机器（macOS：系统设置 → 隐私与安全性
里给终端蓝牙权限）。

## Quick start (CLI)

```bash
python beesim.py                       # 启动终端界面（默认）
python beesim.py --lang zh             # 中文界面（English: --lang en）
python beesim.py scan                  # 列出附近的 BeeSIM* 设备
python beesim.py eid
python beesim.py list [--selector 5C075A9F7090919295]
python beesim.py enable  <iccid>       # 启用后自动软复位生效
python beesim.py disable <iccid>
python beesim.py delete  <iccid>       # 不可逆，务必核对 ICCID
python beesim.py rename  <iccid> "Work SIM"
python beesim.py capacity              # 剩余容量 / 逐卡大小 / 近似总容量
python beesim.py info                  # EID + EUICCInfo1/2 + 中文解读
python beesim.py notifications [--operation INSTALL|ENABLE|DISABLE|DELETE]
python beesim.py notification-send <seq> [--delete-after]   # 默认保留通知
python beesim.py notification-remove <seq>
python beesim.py download "LPA:1$smdp.example.com$MATCHING-ID"
python beesim.py txpower 4             # 0=最小 .. 4=最大
python beesim.py --help                # 完整命令列表
```

全局参数：`--debug`（把全部 APDU 打到 stderr）、`--address`、`--timeout`、
`--store-max-lc`、`--channel`、`--delay-over-counter`、`--rsp-transport web|direct`。

### Terminal UI

`python beesim.py`（或 `tui`）打开界面。启动时选择「中文 / English」；
`--lang zh|en` 跳过选择，运行中按 `l` 切换。语言未选定前不会发起任何蓝牙操作。

侧边栏是连接状态、实时 RSSI、EID 和各功能按钮；中间表格列出配置；底部日志显示
操作、下载进度与 APDU 流量。

| 快捷键 | 功能 | 快捷键 | 功能 |
|---|---|---|---|
| `s` | 扫描并连接 | `m` | 容量 |
| `r` | 刷新 | `N` | 通知 |
| `e` / `d` | 启用 / 停用 | `t` | 发射功率 |
| `x` | 删除 | `a` | 原始 APDU |
| `n` | 改名 | `c` | 断开 |
| `o` | 下载 eSIM | `l` | 切换语言 |
| `i` | 芯片信息 | `q` | 退出 |

## Python API

```python
import asyncio
from beesim_api import connect_card

async def main():
    async with await connect_card() as card:        # 自动扫描 BeeSIM*
        print(await card.eid())
        for p in await card.profiles():
            print(p["iccid"], p["profileState"], p.get("profileNickname"))
        print(await card.info_explained("zh"))      # EUICCInfo2 中文解读
        print(await card.capacity_explained())      # 剩余 / 逐卡 / 近似总容量
        # await card.enable("8985203120001690051")          # reset=True 默认复位
        # await card.download("LPA:1$hthk.esimcase.com$MATCHING-ID")
        # await card.send_notification("7A", delete_after=True)   # 默认保留通知
        # await card.send_notification("7A")

asyncio.run(main())
```

`connect_card(address=..., timeout=45, store_max_lc=120, channel=1,
delay_over_counter=6, gateway=...)` 覆盖默认值。所有方法都是 async，返回普通
dict/list/str/bool。超时或断开后必须重新 `connect_card()`，旧对象不可复用。
会改变卡片状态的方法（`delete`、`firmware_write`、`set_tx_power`、`reset`、
`download`）在源码里标注了危险等级，**不会**弹窗二次确认，调用方自行确认。

## Communication settings

默认值取自官方 BeeSIM Web 2.3.6（`web-api-reference.json`），语义来自
ISO 7816-4 与 GSMA SGP.22。

| 设置 | 默认 | 含义 |
|---|---|---|
| `store_max_lc` | 120 | 单条 STORE DATA（`81 E2`）的数据字节数；ISO 7816-4 短 APDU 的 Lc 只有 1 字节，故范围 1–255。越小分块越多、单条越短。 |
| `timeout` | 30 秒 | 等待卡片经 BLE notify 返回 APDU 响应的最长时间。超时后传输层会使会话失效，必须重新连接再发命令。 |
| `channel` | 1 | ISO 7816-4 补充逻辑通道（MANAGE CHANNEL，`INS=70`）；ES10 的 CLA = `0x80 \| 通道号`。Web 2.3.6 固定通道 1，仅当卡片拒绝时才试 2/3。 |
| `delay_over_counter` | 6 | 连续发送多少条 APDU 后暂停 1.2 秒，给卡片留处理时间。`GET RESPONSE`（`0xC0`）与 `0xFE` 不计数；下载配置包/刷固件时提高到 20。0 关闭节流。 |

## Capacity

`capacity` / `capacity_explained` / `BeeSIMClient.capacity()` 做两件事：

1. **剩余容量** —— 与官方网页「查看剩余可用容量」完全一致：
   `EUICCInfo2.extCardResource.freeNonVolatileMemory` 按 `(bytes / 1024).toFixed(2) + "KB"` 显示。
2. **逐卡近似大小** —— 来自 `GetProfilesInfo`：每个 `ProfileInfo`（tag `E3`）的
   `profileSize`（tag `9F25`，字节），由卡片 `rspCapability` 的
   `profileSizeInProfilesInfoSupport`（bit 14）控制。

**近似总容量 = sum(profileSize) + 剩余容量**。ETSI TS 102 226 §8.2.1.7.2 只定义了
空闲内存，卡上**没有**权威的总容量字段：这个数字不含系统/文件系统开销，且只统计
报告了大小的配置。不支持 bit 14 的卡（本卡 `rspCapability` 为 `0192`）不报告大小，
此时程序如实显示「无法计算」，**绝不**用猜测值代替。

## Notifications

卡片会排队通知（INSTALL / ENABLE / DISABLE / DELETE），需送达其 SM-DP+。本工具通过
`handleNotification` 发送（默认走官方代理）。**发送成功后默认保留卡上的通知**：
官方 Web 会立即删除，但删除不可逆，本工具把它交给调用方显式决定。

需要删除时传参（不分通知类型）：

```bash
python beesim.py notification-send <seq> --delete-after
```
```python
await card.send_notification(seq, delete_after=True)   # 默认 False = 保留
```

发送失败时通知永远保留，重试即可，不要重复下载配置。

> **例外：下载 eSIM 流程仍会自动删除安装通知。** SGP.22 §3.5 规定安装结果经
> ES9+ `HandleNotification` 送达并获 SM-DP+ 确认后，LPA 应调用 ES10b
> `RemoveNotificationFromList`；官方 JS 的 `step4_HandleNotification` 同样如此。
> `download_profile` 第 8 步因此默认删除——安装结果是一次性事务凭证，不删会
> 持续占用卡内 NV 空间、可能被重复发送，并造成卡侧与运营商侧状态不一致。
> 这与「手动发送默认保留」并不矛盾：后者面向用户可能想留痕的通知，删除不可逆；
> 下载通知没有留痕价值，且两端 JS/PY 行为一致。

## 与官方网页的有意差异

记录在 `web-api-reference.json`：

- 链式 GET RESPONSE 遇到空 `90 00` 时最多重试 3 次（与官方 Web 一致），避免返回半截 TLV；
- 只读 ES10 命令在响应 TLV 不完整时自动重读；改状态的命令绝不重放；
- 初始化时校验 SELECT 成功才算会话可用；
- 下载结束后无论成败都尝试把发射功率恢复到 1；
- 发送通知成功后默认**保留**卡上通知（官方 Web 总会删除）；可用
  `--delete-after` / `delete_after=True` 显式删除；
- 切换卡（enable/disable）成功后复位 eUICC（与官方 Web 一致），API 可用
  `reset=False` 跳过；
- EnableProfile 返回 `02` 视为成功（官方 Web 报错）；
- 诊断日志**绝不**自动上传。

平台差异：Windows 无法读取**已连接**设备的 RSSI（见下）；快速重连可能报
`WinError -2147023673`，等几秒重试即可。

## ⚠️ Security warning

**这张卡通过 BLE 暴露完整的 eUICC 管理接口，没有任何访问控制，也无法关闭蓝牙。**
射频范围内的任何 BLE 设备，无需 PIN、配对或绑定，就可以：

- 列出、启用、停用、删除、改名配置（完整 ES10 权限）；
- 安装攻击者控制的配置，再用伪基站服务它 —— 把通常被「双向认证」挡下的 IMSI-catcher
  变成对全部移动数据的中间人，**短信验证码**也一并截获；
- 在选定时刻停用或删除你的 eSIM 作为拒绝服务（可打断短信验证码 / 账号找回）。

已向厂商（BeeSIM）披露；对方回复蓝牙无法硬件关闭，且 PIN 功能「已被移除、基本没用、
未来版本也不会加」。

**现在能做的**：把发射功率降到最低。注意它只是**减小范围，不等于加了认证**——
高增益天线仍可能够到低功率发射：

```bash
python beesim.py txpower 0
```

可随时用 `txpower 4` 或手机上的 SIM Toolkit 菜单改回。真正的修复（强制 PIN、
硬件开关、BLE 绑定加密）只能由厂商做。

## Protocol reference (reverse-engineered)

来源：官方网页 LPA `https://beeesim.com/ble/`（Vue 3 SPA，构建串 *"BeeSIM Web v2.3.6"*），
通过下载并反混淆其 JS chunk 还原。卡片是可通过蓝牙访问的 **GSMA SGP.22 eUICC**。
逆向依据见 `src/`（v2.1.4 快照）与 `web-api-reference.json`（v2.3.6 哈希与合约）。

> 取 JS 的诀窍：CDN 只在请求带 `Accept-Encoding: gzip` 时返回 JS（nginx `gzip_static`，
> 普通请求会 404），用 `curl --compressed` 即可。

**BLE 传输**

| 项 | 值 |
|---|---|
| 设备名过滤 | `namePrefix: "BeeSIM"` |
| GATT 服务 | `0000ae30-0000-1000-8000-00805f9b34fb`（16 位 `0xAE30`） |
| write / notify 特征 | 按属性从服务的特征中挑选，**不**硬编码 UUID |

超过单个 ATT 包的 APDU 被切成 **18 字节分组**；每个包（双向）带 2 字节头：
`总组数, 组号(从 1 开始)`。`index == total` 时响应完整，重组结果**包含末尾的 SW1SW2**。

**初始化序列**（任何 ES10 命令之前）：

```
00 70 80 01 00                      MANAGE CHANNEL — 关闭通道 1
80 AA 00 00 0A A9 08 81 00 82 01 01 83 01 07   厂商「设备特性」
00 70 00 01 00                      MANAGE CHANNEL — 打开通道 1
01 A4 04 00 10 A0000005591010FFFFFFFF8900000100   SELECT ISD-R
```

**ES10 命令**以 BER-TLV 装在 STORE DATA（`81 E2`）里，响应用 GET RESPONSE（`81 C0`，
SW 为 `61 xx` 则继续取）拉回。ICCID 在卡上是**半字节交换**存放的。

| 操作 | 命令 TLV |
|---|---|
| GetEID | `BF3E 03 5C 01 5A` |
| GetEUICCInfo1 / 2 | `BF20 00` / `BF22 00` |
| GetProfilesInfo | `BF2D 00`（或 `BF2D {5C …}` 带标签列表） |
| EnableProfile / DisableProfile | `BF31`/`BF32` `{A0{5A iccid}} 81 01 00` |
| DeleteProfile / SetNickname | `BF33 {5A iccid}` / `BF29 {5A}{90 utf8}` |
| ListNotification / Retrieve / Remove | `BF28 00` / `BF2B …` / `BF30 {80 seq}` |
| AuthenticateServer / PrepareDownload | `BF38 …` / `BF21 …` |
| LoadBoundProfilePackage | BPP 切成 STORE DATA 分块写入 |

厂商命令：`A0 3E <power> 00 00`（发射功率）、`A0 3F 00 00 00`（软复位）、
`00 00 00 00 F4 01 01`（固件进度）。

**下载流程**（卡侧 ES10b 与服务器侧 ES9+ 交错）：
challenge/info1 → `initiateAuthentication` → `AuthenticateServer` →
`authenticateClient` → `PrepareDownload` → `getBoundProfilePackage` →
`LoadBoundProfilePackage` → `handleNotification`。激活码形如
`LPA:1$<smdp>$<matchingId>[$<oid>][$<ccRequired>]`。配置默认安装为**停用**，
需要时 `enable <iccid>`。

**Bluetooth-PIN** 只存在于固件层且处于休眠：网页代码里没有任何 VERIFY/SET/CHANGE-PIN
APDU，`skip_pin` 开关写入后从未被读取。详见上面的安全警告。

> 已在真机端到端验证：BetterRoaming 的 GSMA 测试配置经此工具下载并安装成功。
> 公开免费测试配置时有时无，服务器返回 `matching ID refused` 属正常（见
> <https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/>）。

## Tests

```bash
python -m unittest discover -s tests -v      # 73 项，不需要蓝牙/硬件
```

覆盖 TLV 编解码、APDU 会话、传输分帧、ES10 解析、下载流程、对外 API、HTTP 合约
与无头 TUI。`Dockerfile.test` 在 `python:3.13-slim` 里跑同一套。

静态检查：

```bash
python -m mypy --ignore-missing-imports beesim*.py   # 预期 0 错误
python -m pyflakes beesim*.py tests/*.py             # 预期 0 告警
```

真实硬件上的连接、下载、刷写仍需在真卡上人工验证。
