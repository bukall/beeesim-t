"""Regression tests for the public beesim_api.BeeSIMClient facade.

These tests are fully offline: the BLE/eUICC layers are replaced with mocks.
They verify the contract other programs rely on, not the protocol itself
(that is covered by test_protocol.py / test_web.py).
"""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from beesim_api import BeeSIMClient


def make_client():
    ble = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", disconnect=AsyncMock())
    sim = SimpleNamespace(
        protocol="gsma/rsp/v2.2.2",
        get_eid=AsyncMock(return_value="89049032000001000000296032006412"),
        get_profiles=AsyncMock(return_value=[{"iccid": "8901", "profileState": "ON"}]),
        get_euicc_info1=AsyncMock(return_value={"svn": "2.2.2"}),
        get_euicc_info2=AsyncMock(return_value={
            "svn": "2.2.2", "raw": "BF228202B4",
            "extCardResource": {"installedApplication": 0,
                                "freeNonVolatileMemory": 21217,
                                "freeVolatileMemory": 5048}}),
        list_notifications=AsyncMock(return_value=[{"index": "01"}]),
        retrieve_notification=AsyncMock(return_value=b"\xbf\x2b\x00"),
        send_notification=AsyncMock(return_value={"index": "01"}),
        remove_notification=AsyncMock(return_value=True),
        enable_profile=AsyncMock(return_value=True),
        disable_profile=AsyncMock(return_value=True),
        delete_profile=AsyncMock(return_value=True),
        set_nickname=AsyncMock(return_value=True),
        download_firmware=AsyncMock(),
    )
    euicc = SimpleNamespace(
        check_upgrading=AsyncMock(return_value={"crc": "ABCD", "totalRows": 2, "currentRow": 0}),
        reset=AsyncMock(),
        set_tx_power=AsyncMock(),
        send_command=AsyncMock(return_value=b"\x90\x00"),
        inited=True,
    )
    return BeeSIMClient(ble, sim, euicc)


class PublicApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_context_manager_closes_ble_and_is_idempotent(self):
        card = make_client()
        async with card as opened:
            self.assertIs(opened, card)
            self.assertFalse(card.closed)
            self.assertEqual(card.address, "AA:BB:CC:DD:EE:FF")
            self.assertEqual(card.protocol, "gsma/rsp/v2.2.2")
        self.assertTrue(card.closed)
        card._ble.disconnect.assert_awaited_once()
        await card.close()
        card._ble.disconnect.assert_awaited_once()

    async def test_closed_client_refuses_further_operations(self):
        card = make_client()
        await card.close()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            await card.eid()

    async def test_read_methods_delegate_and_return_plain_data(self):
        card = make_client()
        self.assertEqual(await card.eid(), "89049032000001000000296032006412")
        self.assertEqual(await card.profiles(), [{"iccid": "8901", "profileState": "ON"}])
        self.assertEqual((await card.info())["svn"], "2.2.2")
        self.assertIn("SGP.22 规范版本", await card.info_explained("zh"))
        self.assertEqual(await card.notifications(), [{"index": "01"}])
        self.assertEqual(await card.retrieve_notification("01"), b"\xbf\x2b\x00")
        self.assertEqual(await card.firmware_status(),
                         {"crc": "ABCD", "totalRows": 2, "currentRow": 0})
        self.assertEqual(await card.rssi(), None)

    async def test_capacity_matches_official_display_and_derives_used(self):
        card = make_client()
        data = await card.capacity()
        self.assertEqual(data["freeBytes"], 21217)
        self.assertEqual(data["freeKB"], "20.72KB")
        self.assertIsNone(data["usedBytes"])
        with_total = await card.capacity(total_kb=128)
        self.assertEqual(with_total["totalBytes"], 131072)
        self.assertEqual(with_total["usedBytes"], 131072 - 21217)
        self.assertIn("已消耗容量", await card.capacity_explained(128))

    async def test_enable_disable_refresh_by_default(self):
        card = make_client()
        self.assertTrue(await card.enable("8901"))
        card._euicc.reset.assert_awaited_once()
        self.assertTrue(await card.disable("8901", refresh=False))
        card._euicc.reset.assert_awaited_once()

    async def test_download_parses_activation_code_and_rejects_missing_confirmation(self):
        card = make_client()
        with patch("beesim_api.download_profile", new=AsyncMock(return_value={"iccid": "8901"})) as dl:
            result = await card.download("LPA:1$rsp.example.com$MATCH")
            self.assertEqual(result, {"iccid": "8901"})
            self.assertEqual(dl.call_args.args[2], "rsp.example.com")
            self.assertEqual(dl.call_args.args[3], "MATCH")
        with self.assertRaisesRegex(ValueError, "Confirmation code"):
            await card.download("1$rsp.example.com$MATCH$$1")

    async def test_delete_and_notification_delegation(self):
        card = make_client()
        self.assertTrue(await card.delete("8901"))
        self.assertTrue(await card.rename("8901", "work"))
        self.assertTrue(await card.remove_notification("01"))
        self.assertEqual(await card.send_notification("01"), {"index": "01"})
        self.assertEqual(await card.raw_apdu("A03F000000"), "9000")
        self.assertFalse(card._euicc.inited)


if __name__ == "__main__":
    unittest.main()
