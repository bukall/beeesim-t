"""Bilingual Textual UI. Imported lazily by beesim so the CLI stays independent."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, RichLog, Select, Static

from beesim_i18n import translate, translate_error


def build_app(api):
    class LanguageScreen(ModalScreen[str]):
        BINDINGS = [Binding("escape", "dismiss_language", show=False)]

        def compose(self):
            with Vertical(id="dialog"):
                yield Label("选择界面语言 / Choose language", id="dialog-q")
                yield Button("中文", id="lang-zh", variant="primary")
                yield Button("English", id="lang-en")

        def on_button_pressed(self, event):
            self.dismiss("zh" if event.button.id == "lang-zh" else "en")

        def action_dismiss_language(self):
            # Startup must choose explicitly; Escape can close only later menus.
            if self.app.language_selected:
                self.dismiss(self.app.language)

    class ConfirmScreen(ModalScreen[bool]):
        def __init__(self, question, language):
            super().__init__()
            self.question, self.language = question, language

        def compose(self):
            with Vertical(id="dialog"):
                yield Label(self.question, id="dialog-q", markup=False)
                with Horizontal(id="dialog-buttons"):
                    yield Button(translate("cancel", self.language), id="cancel")
                    yield Button(translate("confirm", self.language), id="confirm", variant="warning")

        def on_button_pressed(self, event):
            self.dismiss(event.button.id == "confirm")

    class FormScreen(ModalScreen[dict | None]):
        def __init__(self, title, fields, language):
            super().__init__()
            self.title_text, self.fields, self.language = title, fields, language

        def compose(self):
            with VerticalScroll(id="dialog"):
                yield Label(self.title_text, id="dialog-q", markup=False)
                for key, label, value, password in self.fields:
                    yield Label(label, markup=False)
                    yield Input(value=value, password=password, id="field-" + key)
                with Horizontal(id="dialog-buttons"):
                    yield Button(translate("cancel", self.language), id="cancel")
                    yield Button(translate("ok", self.language), id="ok", variant="primary")

        def on_mount(self):
            self.query_one(Input).focus()

        def submit(self):
            self.dismiss({key: self.query_one("#field-" + key, Input).value for key, *_ in self.fields})

        def on_input_submitted(self, event):
            if len(self.fields) == 1:
                self.submit()
            else:
                self.focus_next()

        def on_button_pressed(self, event):
            if event.button.id == "ok":
                self.submit()
            else:
                self.dismiss(None)

    class PowerScreen(ModalScreen[int | None]):
        def __init__(self, language):
            super().__init__()
            self.language = language

        def compose(self):
            tr = lambda key: translate(key, self.language)
            with Vertical(id="dialog"):
                yield Label(tr("txpower"), id="dialog-q")
                yield Static(tr("power_hint"))
                levels = [(str(n) + (" — " + tr("power_min" if n == 0 else "power_max") if n in (0, 4) else ""), n) for n in range(5)]
                yield Select(levels, value=1, allow_blank=False, id="tx-level")
                with Horizontal(id="dialog-buttons"):
                    yield Button(tr("cancel"), id="cancel")
                    yield Button(tr("confirm"), id="confirm", variant="primary")

        def on_button_pressed(self, event):
            self.dismiss(self.query_one("#tx-level", Select).value if event.button.id == "confirm" else None)

    class BeeSimApp(App):
        CSS = """
        Screen { layout: vertical; }
        #body { height: 1fr; }
        #sidebar { width: 28; border: round $primary; padding: 1; }
        #sidebar Button { width: 100%; margin-bottom: 1; }
        #status { margin-bottom: 1; }
        #eid { color: $success; }
        #main { width: 1fr; }
        #profiles { height: 1fr; border: round $primary; }
        #log { height: 12; border: round $secondary; padding: 0 1; }
        ModalScreen { align: center middle; background: $background 70%; }
        #dialog { width: 64; max-width: 95%; height: auto; max-height: 95%;
                  padding: 1 2; border: thick $primary; background: $panel; }
        #dialog-q { margin-bottom: 1; text-style: bold; }
        #dialog Input, #dialog Select { margin-bottom: 1; }
        #dialog-buttons { height: auto; align: right middle; margin-top: 1; }
        #dialog-buttons Button { width: auto; margin-left: 1; }
        LanguageScreen Button { width: 100%; margin-top: 1; }
        """
        ACTIONS = [("s", "scan"), ("r", "refresh"), ("e", "enable"), ("d", "disable"),
                   ("x", "delete"), ("n", "rename"), ("o", "download"), ("i", "info"),
                   ("N", "notifications"), ("t", "txpower"), ("a", "apdu"),
                   ("c", "disconnect"), ("l", "language"), ("q", "quit")]
        BINDINGS = [Binding(key, action, "APDU" if action == "apdu" else translate(action, "zh")) for key, action in ACTIONS]
        BUTTONS = ["scan", "refresh", "download", "enable", "disable", "delete", "rename", "txpower",
                   "reset", "info", "notifications", "send_notification", "firmware", "settings", "language", "disconnect"]

        def __init__(self, address=None, language=None, *, debug=False, settings=None, gateway=None):
            super().__init__()
            self.address = address
            self.language = language or "zh"
            self.language_selected = language is not None
            self.apdu_debug = debug
            self.settings = dict(timeout=30.0, store_max_lc=120, channel=1, delay_over_counter=6)
            if settings:
                self.settings.update(settings)
            self.gateway = gateway
            self.client = self.sim = self.euicc = None
            self.busy = False
            self.rssi = None
            self.rssi_ts = 0.0
            self._profiles = []
            self._eid = ""

        def tr(self, key, **values):
            return translate(key, self.language, **values)

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="body"):
                with VerticalScroll(id="sidebar"):
                    yield Static(self.tr("disconnected"), id="status")
                    yield Static("", id="eid", markup=False)
                    yield Static("RSSI —", id="rssi", markup=False)
                    yield Static("", id="devname", markup=False)
                    for name in self.BUTTONS:
                        yield Button(self.tr(name), id="btn-" + name,
                                     variant="success" if name == "scan" else "error" if name == "delete" else "default")
                with Vertical(id="main"):
                    yield DataTable(id="profiles", zebra_stripes=True, cursor_type="row")
                    yield RichLog(id="log", highlight=False, markup=False, wrap=True)
            yield Footer()

        def on_mount(self):
            self.apply_language(self.language, initial=True)
            self.set_interval(1, self._render_rssi)
            if not self.language_selected:
                self.call_after_refresh(lambda: self.push_screen(LanguageScreen(), self.apply_language))
            else:
                self.log_line(self.tr("ready"))

        def apply_language(self, language, initial=False):
            self.language = language
            if not initial:
                self.language_selected = True
            self.title, self.sub_title = "BeeSIM", self.tr("subtitle")
            for name in self.BUTTONS:
                self.query_one("#btn-" + name, Button).label = self.tr(name)
            for key, action in self.ACTIONS:
                self.bind(key, action, description="APDU" if action == "apdu" else self.tr(action))
            self._render_profiles()
            self._render_status()
            self._render_rssi()
            if not initial:
                self.log_line(self.tr("ready"))

        def log_line(self, message):
            self.query_one("#log", RichLog).write(message)

        def progress(self, message):
            self.log_line(self.tr(message))

        def _render_status(self):
            key = "connected" if self.client else "disconnected"
            self.query_one("#status", Static).update(("● " if self.client else "○ ") + self.tr(key))
            for name in self.BUTTONS:
                required = name not in ("scan", "settings", "language")
                self.query_one("#btn-" + name, Button).disabled = self.busy or (required and not self.client)

        def _guard(self, connected=True):
            if not self.language_selected:
                return False
            if self.busy:
                self.log_line(self.tr("busy"))
                return False
            if connected and not self.sim:
                self.log_line(self.tr("not_connected"))
                return False
            return True

        def _start(self, action, callback):
            if not self._guard(connected=action not in ("scan", "settings")):
                return
            self.busy = True
            self._render_status()
            self._job(action, callback)

        @work(group="card", exit_on_error=False)
        async def _job(self, action, callback):
            try:
                self.log_line(self.tr("operation", action=self.tr(action)))
                await callback()
            except Exception as exc:
                self.log_line(self.tr("failed", action=self.tr(action), error=translate_error(exc, self.language)))
                if self.euicc and getattr(self.euicc.t, "_closed", False):
                    await self._disconnect()
            finally:
                self.busy = False
                self._render_status()

        def on_button_pressed(self, event):
            if event.button.id and event.button.id.startswith("btn-"):
                getattr(self, "action_" + event.button.id[4:])()

        def _selected(self):
            table = self.query_one("#profiles", DataTable)
            if not table.row_count:
                self.log_line(self.tr("select_profile"))
                return None
            return str(table.get_row_at(table.cursor_row)[0])

        def _render_profiles(self):
            from rich.text import Text
            table = self.query_one("#profiles", DataTable)
            table.clear(columns=True)
            table.add_columns("ICCID", self.tr("state"), self.tr("name"), self.tr("provider"), self.tr("class"))
            for item in self._profiles:
                table.add_row(Text(item.get("iccid", "?")), Text(self.tr("on" if item.get("profileState") == "ON" else "off")),
                              Text(item.get("profileNickname") or item.get("profileName", "")),
                              Text(item.get("serviceProviderName", "")), Text(self.tr(item.get("profileClass", "test"))))

        async def _load_profiles(self):
            self.log_line(self.tr("reading_profiles"))
            self._profiles = await self.sim.get_profiles("5C075A9F7090919295")
            self._render_profiles()
            self.log_line(self.tr("profile_count", count=len(self._profiles)))

        def action_scan(self):
            if not self._guard(False):
                return
            if self.client:
                self.log_line(self.tr("already_connected"))
                return
            self._start("scan", self._connect)

        async def _connect(self):
            self.query_one("#status", Static).update(self.tr("scanning"))
            try:
                self.client, self.sim, self.euicc = await api.connect(self.address, self.apdu_debug, log=self.progress, **self.settings)
                self.euicc.on_log = self.log_line
                self.log_line(self.tr("reading_eid"))
                self.query_one("#devname", Static).update(str(self.client.address))
                self._eid = await self.sim.get_eid()
                self.query_one("#eid", Static).update("EID " + self._eid)
                await self._load_profiles()
                self._rssi_monitor()
            except BaseException:
                await self._disconnect()
                raise

        def action_refresh(self):
            self._start("refresh", self._load_profiles)

        def _profile_op(self, action):
            if self._guard() and (iccid := self._selected()):
                async def perform():
                    await getattr(self.sim, action + "_profile")(iccid)
                    self.log_line(self.tr("apply_reset"))
                    await self._load_profiles()
                self._start(action, perform)

        def action_enable(self):
            self._profile_op("enable")

        def action_disable(self):
            self._profile_op("disable")

        def action_delete(self):
            if self._guard() and (iccid := self._selected()):
                async def perform():
                    await self.sim.delete_profile(iccid)
                    await self._load_profiles()
                self.push_screen(ConfirmScreen(self.tr("delete_question", iccid=iccid), self.language),
                                 lambda yes: self._start("delete", perform) if yes else None)

        def _form(self, key, callback, value="", password=False):
            self.push_screen(FormScreen(self.tr(key), [("value", self.tr(key), value, password)], self.language),
                             lambda result: callback(result["value"]) if result is not None else None)

        def action_rename(self):
            if self._guard() and (iccid := self._selected()):
                def submit(name):
                    if not name.strip():
                        return
                    async def perform():
                        await self.sim.set_nickname(iccid, name)
                        await self._load_profiles()
                    self._start("rename", perform)
                self._form("nickname", submit)

        def action_txpower(self):
            if self._guard():
                self.push_screen(PowerScreen(self.language), lambda level: self._start("txpower", lambda: self.sim.set_tx_power(level)) if level is not None else None)

        def action_reset(self):
            if self._guard():
                async def perform():
                    await self.euicc.reset()
                    self.log_line(self.tr("reset_sent"))
                    await self._disconnect()
                self.push_screen(ConfirmScreen(self.tr("reset_question"), self.language),
                                 lambda yes: self._start("reset", perform) if yes else None)

        def action_download(self):
            if not self._guard():
                return
            def activation(code):
                try:
                    smdp, matching, required = api.parse_activation_code(code)
                except ValueError as exc:
                    self.log_line(self.tr("failed", action=self.tr("download"), error=str(exc)))
                    return
                def confirmation(confirmation_code):
                    if required and not confirmation_code:
                        self.log_line(self.tr("confirmation_required"))
                        return
                    async def perform():
                        await api.download_profile(self.sim, self.euicc, smdp, matching, confirmation_code or None,
                                                   log=self.progress, gateway=self.gateway)
                        self.log_line(self.tr("download_ok"))
                        await self._load_profiles()
                    from beesim_web import DirectRSP
                    self.push_screen(ConfirmScreen(self.tr("direct_question" if isinstance(self.gateway, DirectRSP) else "proxy_question"), self.language),
                                     lambda yes: self._start("download", perform) if yes else None)
                self._form("confirmation_code", confirmation, password=True)
            self._form("activation", activation)

        def action_info(self):
            async def perform():
                self.log_line(json.dumps(await self.sim.get_euicc_info2(), ensure_ascii=False, indent=2))
            self._start("info", perform)

        def action_notifications(self):
            async def perform():
                items = await self.sim.list_notifications(decoded=True)
                self.log_line(json.dumps(items, ensure_ascii=False, indent=2) if items else self.tr("no_notifications"))
            self._start("notifications", perform)

        def action_send_notification(self):
            if not self._guard():
                return
            def submit(seq):
                try:
                    if not api.h2b(seq):
                        return
                except ValueError as exc:
                    self.log_line(str(exc))
                    return
                self.push_screen(ConfirmScreen(self.tr("send_question", seq=seq), self.language),
                                 lambda yes: self._start("send_notification", lambda: self.sim.send_notification(seq, self.gateway)) if yes else None)
            self._form("notification_seq", submit)

        def action_apdu(self):
            if not self._guard():
                return
            def submit(value):
                try:
                    command = api.h2b(value)
                    if len(command) < 4:
                        raise ValueError("APDU")
                except ValueError:
                    self.log_line(self.tr("raw_apdu"))
                    return
                async def perform():
                    try:
                        self.log_line(api.b2h(await self.euicc.send_command(command, reinit_on_6881=False)))
                    finally:
                        self.euicc.inited = False
                self.push_screen(ConfirmScreen(self.tr("raw_question", apdu=api.b2h(command)), self.language),
                                 lambda yes: self._start("apdu", perform) if yes else None)
            self._form("raw_apdu", submit)

        def action_settings(self):
            if not self._guard(False):
                return
            fields = [(key, self.tr(label), str(self.settings[key]), False) for key, label in
                      (("store_max_lc", "store_max_lc"), ("timeout", "reply_timeout"), ("channel", "channel"), ("delay_over_counter", "delay_counter"))]
            def submit(result):
                if result is None:
                    return
                try:
                    settings = {key: float(value) if key == "timeout" else int(value) for key, value in result.items()}
                    if not 1 <= settings["store_max_lc"] <= 255 or not 1 <= settings["channel"] <= 3 or not 0 < settings["timeout"] <= 300 or not 0 <= settings["delay_over_counter"] <= 1000:
                        raise ValueError()
                    self.settings.update(settings)
                    self.log_line(self.tr("settings_saved"))
                except ValueError:
                    self.log_line(self.tr("settings_invalid"))
            self.push_screen(FormScreen(self.tr("settings"), fields, self.language), submit)

        def action_firmware(self):
            if not self._guard():
                return
            def submit(path):
                try:
                    content = api.parse_firmware_text(Path(path).expanduser().read_text())
                except (OSError, ValueError):
                    self.log_line(self.tr("firmware_invalid"))
                    return
                async def check():
                    progress = await self.euicc.check_upgrading()
                    if progress["crc"] == content["crc"] and (not progress["totalRows"] or progress["currentRow"] >= progress["totalRows"]):
                        self.log_line(self.tr("firmware_current"))
                        return
                    # Matching CRC and total identify this exact firmware batch.
                    resume = progress["crc"] == content["crc"] and progress["totalRows"] == len(content["rows"])
                    start = progress["currentRow"] + 1 if resume else 1
                    rows = content["rows"][start-1:]
                    question = self.tr("firmware_resume", row=start) if resume else self.tr("firmware_question", name=Path(path).name, total=len(rows))
                    async def perform():
                        await self.sim.download_firmware(rows, len(content["rows"]), start, self.log_line)
                        self.log_line(self.tr("reset_sent"))
                        await self._disconnect()
                    # Open after the check worker releases its busy flag.
                    self.call_after_refresh(lambda: self.push_screen(ConfirmScreen(question, self.language),
                                            lambda yes: self._start("firmware", perform) if yes else None))
                self._start("firmware", check)
            self._form("firmware_path", submit)

        def action_language(self):
            if self._guard(False):
                self.push_screen(LanguageScreen(), self.apply_language)

        async def _disconnect(self):
            client = self.client
            self.client = self.sim = self.euicc = None
            self.rssi = None
            self._profiles = []
            self._eid = ""
            self.query_one("#eid", Static).update("")
            self.query_one("#devname", Static).update("")
            self._render_profiles()
            if client:
                try:
                    await client.disconnect()
                except Exception as exc:
                    self.log_line(self.tr("failed", action=self.tr("disconnect"), error=translate_error(exc, self.language)))

        def action_disconnect(self):
            self._start("disconnect", self._disconnect)

        async def action_quit(self):
            workers = [worker for worker in self.workers if worker.group == "card"]
            for worker in workers:
                worker.cancel()
            if workers:
                await asyncio.gather(*(worker.wait() for worker in workers), return_exceptions=True)
            try:
                await self._disconnect()
            finally:
                self.exit()

        def _render_rssi(self):
            try:
                widget = self.query_one("#rssi", Static)
            except NoMatches:
                # Timer ticks can land before the screen is composed (Textual 8).
                return
            text = "RSSI —"
            if self.client and self.rssi is not None:
                bars = max(0, min(4, (self.rssi + 100) // 12))
                text = "RSSI " + "▂▄▆█"[:bars] + "·" * (4-bars) + f" {self.rssi} dBm"
                if time.monotonic() - self.rssi_ts > 5:
                    text += " (" + self.tr("stale") + ")"
            widget.update(text)

        @work(exclusive=True, group="rssi", exit_on_error=False)
        async def _rssi_monitor(self):
            warned = False
            while self.client:
                if not self.busy and not getattr(self.client, "is_connected", True):
                    await self._disconnect()
                    self._render_status()
                    break
                value = await api.read_rssi(self.client)
                if value is not None:
                    self.rssi, self.rssi_ts = value, time.monotonic()
                elif not warned:
                    self.log_line(self.tr("rssi_unavailable"))
                    warned = True
                await asyncio.sleep(2)

    return BeeSimApp
