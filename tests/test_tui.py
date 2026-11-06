import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from textual.widgets import Button, DataTable, Input, Label, Static

import beesim as b
from beesim_i18n import TEXT, translate


class LanguageTests(unittest.TestCase):
    def test_language_catalog_is_complete_and_formats(self):
        for key, pair in TEXT.items():
            self.assertEqual(len(pair), 2, key)
            self.assertTrue(all(isinstance(value, str) and value for value in pair), key)
        self.assertEqual(translate("profile_count", "zh", count=2), "共 2 个配置。")
        self.assertEqual(translate("profile_count", "en", count=2), "2 profile(s).")


class TUITests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_requires_language_and_does_not_scan(self):
        app = b._build_tui_app()()
        with patch.object(b, "connect", new=AsyncMock()) as connect:
            async with app.run_test(size=(110, 40)) as pilot:
                await pilot.pause()
                self.assertEqual(app.screen.__class__.__name__, "LanguageScreen")
                self.assertFalse(app.language_selected)
                await pilot.click("#lang-zh")
                await pilot.pause()
                self.assertTrue(app.language_selected)
                self.assertEqual(str(app.query_one("#btn-scan", Button).label), "扫描并连接")
                connect.assert_not_awaited()

    async def test_english_startup_and_language_switch(self):
        app = b._build_tui_app()()
        async with app.run_test(size=(110, 40)) as pilot:
            await pilot.pause()
            await pilot.click("#lang-en")
            await pilot.pause()
            self.assertEqual(str(app.query_one("#btn-download", Button).label), "Download eSIM")
            app.action_language()
            await pilot.pause()
            await pilot.click("#lang-zh")
            await pilot.pause()
            self.assertEqual(str(app.query_one("#btn-download", Button).label), "下载 eSIM")
            self.assertEqual(app.sub_title, "蓝牙 eUICC 管理工具")

    async def test_settings_validate_and_localize(self):
        app = b._build_tui_app()(language="zh")
        async with app.run_test(size=(110, 40)) as pilot:
            app.action_settings()
            await pilot.pause()
            app.screen.query_one("#field-store_max_lc", Input).value = "121"
            app.screen.query_one("#field-timeout", Input).value = "45"
            await pilot.click("#ok")
            await pilot.pause()
            self.assertEqual(app.settings["store_max_lc"], 121)
            self.assertEqual(app.settings["timeout"], 45)

    async def test_localized_profile_and_delete_cancel(self):
        app = b._build_tui_app()(language="zh")
        app.client = SimpleNamespace(disconnect=AsyncMock())
        app.sim = SimpleNamespace(delete_profile=AsyncMock())
        app._profiles = [{"iccid": "8901", "profileState": "ON", "profileNickname": "中文[昵称]", "profileClass": "operational"}]
        async with app.run_test(size=(110, 40)) as pilot:
            table = app.query_one("#profiles", DataTable)
            self.assertIn("中文[昵称]", str(table.get_row_at(0)[2]))
            self.assertIn("已启用", str(table.get_row_at(0)[1]))
            app.action_delete()
            await pilot.pause()
            self.assertIn("无法撤销", str(app.screen.query_one("#dialog-q", Label).render()))
            await pilot.click("#cancel")
            app.sim.delete_profile.assert_not_awaited()

    async def test_connection_initialization_failure_disconnects(self):
        app = b._build_tui_app()(language="en")
        client = SimpleNamespace(address="test", disconnect=AsyncMock())
        sim = SimpleNamespace(get_eid=AsyncMock(side_effect=RuntimeError("SELECT failed")))
        e = SimpleNamespace(on_log=None)
        async with app.run_test(size=(110, 40)) as pilot:
            with patch.object(b, "connect", new=AsyncMock(return_value=(client, sim, e))):
                app.action_scan()
                await pilot.pause()
                await app.workers.wait_for_complete()
                self.assertIsNone(app.client)
                self.assertFalse(app.busy)
                client.disconnect.assert_awaited_once()

    async def test_both_languages_have_confirmation_and_power_dialogs(self):
        for language, cancel in (("zh", "取消"), ("en", "Cancel")):
            app = b._build_tui_app()(language=language)
            app.client = SimpleNamespace(disconnect=AsyncMock())
            app.sim = SimpleNamespace(set_tx_power=AsyncMock())
            async with app.run_test(size=(110, 40)) as pilot:
                app.action_txpower()
                await pilot.pause()
                self.assertEqual(str(app.screen.query_one("#cancel", Button).label), cancel)
                await pilot.click("#cancel")
                app.sim.set_tx_power.assert_not_awaited()

    async def test_connect_refresh_and_disconnect(self):
        app = b._build_tui_app()(language="zh")
        client = SimpleNamespace(address="test", disconnect=AsyncMock())
        sim = SimpleNamespace(get_eid=AsyncMock(return_value="1234"), get_profiles=AsyncMock(return_value=[]))
        e = SimpleNamespace(on_log=None, t=SimpleNamespace(_closed=False))
        async with app.run_test(size=(110, 40)) as pilot:
            with patch.object(b, "connect", new=AsyncMock(return_value=(client, sim, e))):
                app.action_scan()
                await pilot.pause()
                self.assertIs(app.client, client)
                self.assertFalse(app.busy)
                sim.get_profiles.assert_awaited_with("5C075A9F7090919295")
                app.action_disconnect()
                await pilot.pause()
                self.assertIsNone(app.client)
                client.disconnect.assert_awaited_once()

    async def test_physical_disconnect_updates_ui(self):
        app = b._build_tui_app()(language="zh")
        client = SimpleNamespace(is_connected=False, disconnect=AsyncMock())
        app.client = client
        app.sim = SimpleNamespace()
        async with app.run_test(size=(110, 40)) as pilot:
            app._rssi_monitor()
            await pilot.pause()
            self.assertIsNone(app.client)
            self.assertTrue(app.query_one("#btn-refresh", Button).disabled)

    async def test_download_requests_confirmation_code_and_route_confirmation(self):
        app = b._build_tui_app()(language="zh")
        app.client = SimpleNamespace(disconnect=AsyncMock())
        app.sim = SimpleNamespace(get_profiles=AsyncMock(return_value=[]))
        app.euicc = SimpleNamespace(t=SimpleNamespace(_closed=False))
        async with app.run_test(size=(110, 40)) as pilot:
            with patch.object(b, "download_profile", new=AsyncMock()) as download:
                app.action_download()
                await pilot.pause()
                app.screen.query_one(Input).value = "LPA:1$rsp.example.com$test$$1"
                await pilot.click("#ok")
                await pilot.pause()
                self.assertIn("确认码", str(app.screen.query_one("#dialog-q", Label).render()))
                app.screen.query_one(Input).value = "1234"
                await pilot.click("#ok")
                await pilot.pause()
                self.assertIn("官方代理", str(app.screen.query_one("#dialog-q", Label).render()))
                download.assert_not_awaited()
                await pilot.click("#confirm")
                await pilot.pause()
                self.assertEqual(download.call_args.args[4], "1234")

    async def test_info_screen_shows_json_and_chinese_explanation(self):
        app = b._build_tui_app()(language="zh")
        app.client = SimpleNamespace(disconnect=AsyncMock())
        app.sim = SimpleNamespace(get_euicc_info2=AsyncMock(
            return_value={"svn": "2.2.2", "euiccFirmwareVer": "1.3.6", "raw": "BF22"}))
        app.euicc = SimpleNamespace(t=SimpleNamespace(_closed=False))
        async with app.run_test(size=(110, 40)) as pilot:
            app.action_info()
            await pilot.pause()
            await app.workers.wait_for_complete()
            self.assertEqual(app.screen.__class__.__name__, "InfoScreen")
            self.assertIn('"svn": "2.2.2"',
                          str(app.screen.query_one("#info-raw", Static).render()))
            self.assertIn("SGP.22 规范版本",
                         str(app.screen.query_one("#info-explain", Static).render()))
            await pilot.click("#ok")
            await pilot.pause()
            self.assertNotEqual(app.screen.__class__.__name__, "InfoScreen")
