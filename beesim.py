#!/usr/bin/env python3
"""
beeesim-t 命令行入口（CLI）。

本文件只负责 argparse 命令解析与分发（_run / main），**不**向旧代码 re-export
任何内部名字——请直接 import 需要的模块：

  * beesim_api.BeeSIMClient —— 高层异步客户端（推荐给集成方）
  * beesim_tlv / beesim_protocol / beesim_transport / beesim_euicc / beesim_download
    —— 需要精细控制时的分层 API

分层依赖（自上而下，无循环）
----------------------------
  beesim_tlv        纯字节 / BER-TLV
    ^  beesim_protocol   常量与协议数据解析
    ^  beesim_transport  BLE 帧与连接（依赖 bleak）
    ^  beesim_euicc      APDU 会话与 ES10 命令
    ^  beesim_download   SGP.22 下载流程
    ^  beesim_api        对外高层客户端
  beesim_tui / beesim.py 通过显式 import 使用以上各层。

用法见 README.md 或 `python beesim.py --help`。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from beesim_download import download_profile
from beesim_protocol import (
    NAME_PREFIX, capacity_data, describe_capacity, describe_euicc_info,
    parse_activation_code, parse_firmware_text,
)
from beesim_tlv import b2h, h2b
from beesim_transport import BleakScanner, connect


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
            eid = await sim.get_eid()
            info1 = await sim.get_euicc_info1()
            info2 = await sim.get_euicc_info2()
            print("EID       :", eid)
            print("EUICCInfo1:", json.dumps(info1, indent=2, ensure_ascii=False))
            print("EUICCInfo2:", json.dumps(info2, indent=2, ensure_ascii=False))
            print()
            print(describe_euicc_info(info1, title="EUICCInfo1"))
            print()
            print(describe_euicc_info(info2, title="EUICCInfo2"))
        elif args.command == "eid":
            print(await sim.get_eid())
        elif args.command == "capacity":
            info = await sim.get_euicc_info2()
            profiles = await sim.get_profiles()
            data = capacity_data(info, profiles)
            print(json.dumps(data, indent=2, ensure_ascii=False))
            print()
            print(describe_capacity(data))
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
# Terminal UI (Textual) — imported lazily so the CLI works without it
# --------------------------------------------------------------------------- #
def _build_tui_app():
    """Import Textual only when requested; the TUI imports the core layers directly."""
    try:
        from beesim_tui import build_app
    except ImportError as exc:
        raise RuntimeError("The TUI needs Textual: pip install -r requirements.txt") from exc
    return build_app()


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
    sub.add_parser("capacity", help="free capacity, per-profile size and approximate total")
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
