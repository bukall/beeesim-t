import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from textual.widgets import Button, DataTable, Input, Label, Static

from beesim_i18n import TEXT, translate

from beesim_tui import build_app

class LanguageTests(unittest.TestCase):
    def test_language_catalog_is_complete_and_formats(self):
        for key, pair in TEXT.items():
            self.assertEqual(len(pair), 2, key)
            self.assertTrue(all(isinstance(value, str) and value for value in pair), key)
        self.assertEqual(translate("profile_count", "zh", count=2), "共 2 个配置。")
        self.assertEqual(translate("profile_count", "en", count=2), "2 profile(s).")
        self.assertIn("Windows", translate("rssi_unavailable", "zh"))
        self.assertIn("OS limitation", translate("rssi_unavailable", "en"))


class TUITests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_requires_language_and_does_not_scan(self):
        app = build_app()()
        with patch("beesim_tui.connect", new=AsyncMock()) as connect:
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
        app = build_app()()
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

    async def test_settings_show_detailed_hints_in_both_languages(self):
        for language, expected in (("zh", "ISO 7816-4"), ("en", "one-byte Lc")):
            with self.subTest(language=language):
                app = build_app()(language=language)
                async with app.run_test(size=(140, 50)) as pilot:
                    app.action_settings()
                    await pilot.pause()
                    hints = [str(w.render()) for w in app.screen.query(".field-hint")]
                    self.assertEqual(len(hints), 4)
                    self.assertTrue(all(len(h) > 40 for h in hints))
                    self.assertTrue(any(expected in h for h in hints), hints)

    async def test_settings_validate_and_localize(self):
        app = build_app()(language="zh")
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
        app = build_app()(language="zh")
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
        app = build_app()(language="en")
        client = SimpleNamespace(address="test", disconnect=AsyncMock())
        sim = SimpleNamespace(get_eid=AsyncMock(side_effect=RuntimeError("SELECT failed")))
        e = SimpleNamespace(on_log=None)
        async with app.run_test(size=(110, 40)) as pilot:
            with patch("beesim_tui.connect", new=AsyncMock(return_value=(client, sim, e))):
                app.action_scan()
                await pilot.pause()
                await app.workers.wait_for_complete()
                self.assertIsNone(app.client)
                self.assertFalse(app.busy)
                client.disconnect.assert_awaited_once()

    async def test_both_languages_have_confirmation_and_power_dialogs(self):
        for language, cancel in (("zh", "取消"), ("en", "Cancel")):
            app = build_app()(language=language)
            app.client = SimpleNamespace(disconnect=AsyncMock())
            app.sim = SimpleNamespace(set_tx_power=AsyncMock())
            async with app.run_test(size=(110, 40)) as pilot:
                app.action_txpower()
                await pilot.pause()
                self.assertEqual(str(app.screen.query_one("#cancel", Button).label), cancel)
                await pilot.click("#cancel")
                app.sim.set_tx_power.assert_not_awaited()

    async def test_connect_refresh_and_disconnect(self):
        app = build_app()(language="zh")
        client = SimpleNamespace(address="test", disconnect=AsyncMock())
        sim = SimpleNamespace(get_eid=AsyncMock(return_value="1234"), get_profiles=AsyncMock(return_value=[]))
        e = SimpleNamespace(on_log=None, t=SimpleNamespace(_closed=False))
        async with app.run_test(size=(110, 40)) as pilot:
            with patch("beesim_tui.connect", new=AsyncMock(return_value=(client, sim, e))):
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
        app = build_app()(language="zh")
        client = SimpleNamespace(is_connected=False, disconnect=AsyncMock())
        app.client = client
        app.sim = SimpleNamespace()
        async with app.run_test(size=(110, 40)) as pilot:
            app._rssi_monitor()
            await pilot.pause()
            self.assertIsNone(app.client)
            self.assertTrue(app.query_one("#btn-refresh", Button).disabled)

    async def test_download_requests_confirmation_code_and_route_confirmation(self):
        app = build_app()(language="zh")
        app.client = SimpleNamespace(disconnect=AsyncMock())
        app.sim = SimpleNamespace(get_profiles=AsyncMock(return_value=[]))
        app.euicc = SimpleNamespace(t=SimpleNamespace(_closed=False))
        async with app.run_test(size=(110, 40)) as pilot:
            with patch("beesim_tui.download_profile", new=AsyncMock()) as download:
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
        app = build_app()(language="zh")
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

    async def test_capacity_screen_shows_free_per_profile_and_approx_total(self):
        app = build_app()(language="zh")
        app.client = SimpleNamespace(disconnect=AsyncMock())
        app.sim = SimpleNamespace(
            get_euicc_info2=AsyncMock(return_value={
                "extCardResource": {"installedApplication": 0,
                                    "freeNonVolatileMemory": 21217,
                                    "freeVolatileMemory": 5048}}),
            get_profiles=AsyncMock(return_value=[
                {"iccid": "8901", "profileNickname": "A", "profileSize": 20480},
                {"iccid": "8902", "profileNickname": "B", "profileSize": 40960},
            ]))
        app.euicc = SimpleNamespace(t=SimpleNamespace(_closed=False))
        async with app.run_test(size=(110, 40)) as pilot:
            app.action_capacity()
            await pilot.pause()
            await app.workers.wait_for_complete()
            self.assertEqual(app.screen.__class__.__name__, "InfoScreen")
            body = str(app.screen.query_one("#info-explain", Static).render())
            self.assertIn("20.72KB", body)   # 剩余可用容量（官方换算）
            self.assertIn("A: 20.00KB", body)  # 逐卡近似大小
            self.assertIn("近似总容量", body)  # 已安装合计 + 剩余
