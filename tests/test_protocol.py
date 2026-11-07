import asyncio
from collections import deque
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from beesim_euicc import BeeSim, Euicc
from beesim_protocol import SERVICE_UUID, _parse_profile, capacity_data, describe_capacity, describe_euicc_info, format_capacity_kb, parse_activation_code, parse_firmware_text
from beesim_tlv import find_tag, parse_tlv, tlv
from beesim_transport import BeeSimTransport, connect, read_rssi

class ScriptedTransport:
    def __init__(self, responses):
        self.responses = deque(bytes.fromhex(x) if isinstance(x, str) else x for x in responses)
        self.commands = []

    async def send(self, command):
        self.commands.append(command)
        await asyncio.sleep(0)
        if not self.responses:
            raise AssertionError("Unexpected APDU: " + command.hex())
        return self.responses.popleft()


def euicc(responses):
    return Euicc(ScriptedTransport(responses), delay_over_counter=0)


def response_sequence(raw):
    return ["9000"] * 4 + [bytes([0x61, len(raw)]), raw + bytes.fromhex("9000")]


class CodecTests(unittest.TestCase):
    def test_ber_length_boundaries(self):
        for length, prefix in ((127, "907F"), (128, "908180"), (255, "9081FF"), (256, "90820100")):
            with self.subTest(length=length):
                encoded = tlv(0x90, b"a" * length)
                self.assertTrue(encoded.hex().upper().startswith(prefix))
                self.assertEqual(parse_tlv(encoded)[0]["value"], b"a" * length)

    def test_malformed_tlv_rejected(self):
        for raw in ("BF", "BF3E", "9080", "908201", "900301", "A0029001"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_tlv(bytes.fromhex(raw))

    def test_partial_tlv_reports_truncated_value(self):
        with self.assertRaisesRegex(ValueError, "Truncated TLV value"):
            parse_tlv(bytes.fromhex("BF3E03"))

    def test_activation_codes(self):
        self.assertEqual(parse_activation_code("LPA:1$rsp.example.com$abc$$1"), ("rsp.example.com", "abc", True))
        self.assertEqual(parse_activation_code("1$rsp.example.com"), ("rsp.example.com", "", False))
        with self.assertRaises(ValueError):
            parse_activation_code("1$https://bad/path$abc")

    def test_firmware_parser(self):
        data = parse_firmware_text("F000FEF00001020304ABCD\nF200\n")
        self.assertEqual(data["crc"], "ABCD")
        self.assertEqual(len(data["rows"]), 2)
        for invalid in ("F001\nF200", "F000FEF00001020304ABCD\nF200\nF001", "XYZ"):
            with self.assertRaises(ValueError):
                parse_firmware_text(invalid)


class InitializationTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_6a86_proceeds_to_select(self):
        e = euicc(["6200", "9000", "6A86", "9000"])
        await e.init()
        self.assertTrue(e.inited)
        self.assertEqual([x.hex().upper() for x in e.t.commands], [
            "0070800100", "80AA00000AA9088100820101830107", "0070000100",
            "01A4040010A0000005591010FFFFFFFF8900000100"])

    async def test_select_failure_is_not_success_and_can_retry(self):
        e = euicc(["6200", "9000", "6A86", "6A82"] + ["9000"] * 4)
        with self.assertRaisesRegex(RuntimeError, "SELECT.*6A82.*6A86"):
            await e.init()
        self.assertFalse(e.inited)
        await e.init()
        self.assertTrue(e.inited)
        self.assertEqual(len(e.t.commands), 8)

    async def test_select_get_response(self):
        e = euicc(["9000", "9000", "9000", "6102", "01029000"])
        await e.init()
        self.assertTrue(e.inited)
        self.assertEqual(e.t.commands[-1], bytes.fromhex("81C0000002"))

    async def test_6881_recovers_once(self):
        e = euicc(["6881"] + ["9000"] * 4 + ["9000"])
        e.inited = True
        await e.send_command(bytes.fromhex("81E2910000"))
        self.assertEqual(e.t.commands[0], e.t.commands[-1])
        self.assertEqual(len(e.t.commands), 6)

    async def test_store_fe_and_read_fe(self):
        e = euicc(["00FE", "05FE", "00FE", "01026103", "0304059000"])
        response = await e.store_bytes(b"a" * 121)
        self.assertEqual(response, bytes.fromhex("6105"))
        self.assertEqual(e.t.commands[0][:5], bytes.fromhex("81E2110078"))
        self.assertEqual(e.t.commands[1][:5], bytes.fromhex("81E2910101"))
        self.assertEqual(await e.get_response(5), bytes.fromhex("0102030405"))
        self.assertEqual([x[1] for x in e.t.commands[2:]], [0xC0, 0xFE, 0xC0])

    async def test_6c_uses_requested_length(self):
        e = euicc(["6C02", "AABB9000"])
        self.assertEqual(await e.get_response(4), bytes.fromhex("AABB"))
        self.assertEqual(e.t.commands[-1][-1], 2)

    async def test_transactions_do_not_interleave_store_and_read(self):
        e = euicc(["9000"] * 4 + ["6101", "AA9000", "6101", "BB9000"])
        first, second = await asyncio.gather(e.store_and_read(b"a"), e.store_and_read(b"b"))
        self.assertEqual((first, second), (b"\xaa", b"\xbb"))
        self.assertEqual([x[1] for x in e.t.commands[4:]], [0xE2, 0xC0, 0xE2, 0xC0])

    async def test_low_level_chained_writes_are_atomic(self):
        e = euicc(["9000"] * 4)
        await asyncio.gather(e.store_bytes(b"a" * 121), e.store_bytes(b"b" * 121))
        self.assertEqual([(x[3], chr(x[5])) for x in e.t.commands], [(0, "a"), (1, "a"), (0, "b"), (1, "b")])

    async def test_short_apdu_rejected_before_transport(self):
        e = euicc([])
        with self.assertRaisesRegex(ValueError, "header"):
            await e.send_command(b"a")
        self.assertEqual(e.t.commands, [])

    async def test_throttle_exempts_get_response_trigger(self):
        e = euicc(["9000", "9000", "9000"])
        e.delay_over_counter = 1
        with patch("beesim_euicc.asyncio.sleep", new=AsyncMock()) as sleep:
            await e.send_command(bytes.fromhex("81E2910000"))
            await e.send_command(bytes.fromhex("81C0000000"))
            await e.send_command(bytes.fromhex("81E2910000"))
            # ScriptedTransport also yields via sleep(0); only count 1.2s waits.
            self.assertEqual(sum(call.args == (1.2,) for call in sleep.call_args_list), 1)

    async def test_empty_90_00_retries_instead_of_truncating_tlv(self):
        # The Web bundle retries an empty 90 00: the card may not have the next
        # GET RESPONSE segment ready yet. Returning early yields a half TLV.
        e = euicc(["9000"] * 4 + ["6105", "BF3E036103", "9000", "5C015A9000"])
        r = await e.store_and_read(bytes.fromhex("BF3E035C015A"))
        self.assertEqual(r, bytes.fromhex("BF3E035C015A"))
        self.assertEqual(find_tag(parse_tlv(r), "BF3E", "5C"), b"\x5a")
        reads = [x for x in e.t.commands if x[1] == 0xC0]
        self.assertEqual(len(reads), 3)


class InfoExplanationTests(unittest.TestCase):
    def test_chinese_explanation_covers_parsed_fields_and_raw(self):
        info = {
            "profileVersion": "2.1.0", "svn": "2.2.2", "euiccFirmwareVer": "1.3.6",
            "extCardResource": {"installedApplication": 3, "freeNonVolatileMemory": 12345,
                                "freeVolatileMemory": 678},
            "uiccCapability": "AABB", "ppVersion": "0.0.1", "raw": "BF228202B4",
        }
        text = describe_euicc_info(info, "zh", "EUICCInfo2")
        self.assertIn("EUICCInfo2 · 中文解读", text)
        for label in ("基础配置包版本", "SGP.22 规范版本", "芯片固件版本", "卡内资源",
                      "UICC 能力", "保护轮廓版本"):
            self.assertIn(label, text)
        self.assertIn("2.2.2", text)
        self.assertIn("空闲非易失存储(字节)=12345", text)
        self.assertIn("raw: 卡片返回的原始 BER-TLV", text)

    def test_english_explanation_and_unmapped_field(self):
        text = describe_euicc_info({"svn": "2.2.2", "unknownTag": "0102"}, "en", "EUICCInfo2")
        self.assertIn("explained", text)
        self.assertIn("SGP.22 specification version", text)
        self.assertIn("unmapped field", text)
        self.assertNotIn("中文", text)


class RSSITests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_backend_rssi_returns_none(self):
        self.assertIsNone(await read_rssi(SimpleNamespace()))

    async def test_backend_rssi_is_used_when_available(self):
        self.assertEqual(await read_rssi(SimpleNamespace(get_rssi=lambda: -63)), -63)

        async def coroutine_rssi():
            return -70
        self.assertEqual(await read_rssi(
            SimpleNamespace(_backend=SimpleNamespace(get_rssi=coroutine_rssi))), -70)


class ReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_truncated_read_response_is_replayed(self):
        full = tlv([0xBF, 0x2D], tlv(0xA0, tlv(0xE3, tlv(0x5A, bytes.fromhex("9810")))))
        truncated = bytes.fromhex("BF2D050102")  # declares 5 value bytes, has 2
        responses = ["9000"] * 4 + [bytes([0x61, len(truncated)]),
                                    truncated + bytes.fromhex("9000"),
                                    bytes([0x61, len(full)]),
                                    full + bytes.fromhex("9000")]
        sim = BeeSim(euicc(responses))
        profiles = await sim.get_profiles()
        self.assertEqual(profiles[0]["iccid"], "8901")
        self.assertEqual(len([x for x in sim.e.t.commands if x[1] == 0xE2]), 2)

    async def test_state_changing_command_is_never_replayed(self):
        truncated = bytes.fromhex("BF310301")
        responses = ["9000"] * 4 + [bytes([0x61, len(truncated)]),
                                    truncated + bytes.fromhex("9000")]
        sim = BeeSim(euicc(responses))
        with self.assertRaises(ValueError):
            await sim.enable_profile("8901")
        self.assertEqual(len([x for x in sim.e.t.commands if x[1] == 0xE2]), 1)


class CapacityTests(unittest.TestCase):
    INFO = {"extCardResource": {"installedApplication": 0,
                                "freeNonVolatileMemory": 21214,
                                "freeVolatileMemory": 5098}}

    def test_official_kb_format(self):
        # 官方 JS: (bytes / 1024).toFixed(2) + "KB"
        self.assertEqual(format_capacity_kb(21217), "20.72KB")
        self.assertEqual(format_capacity_kb(1024), "1.00KB")
        self.assertEqual(format_capacity_kb(0), "0.00KB")

    def test_profile_size_field_is_parsed(self):
        e3 = tlv(0xE3, tlv(0x5A, bytes.fromhex("9810")),
                   tlv([0x9F, 0x25], bytes.fromhex("0003E8")))
        profile = _parse_profile(parse_tlv(e3)[0])
        self.assertEqual(profile["profileSize"], 1000)

    def test_capacity_without_profile_sizes(self):
        data = capacity_data(self.INFO)
        self.assertEqual(data["freeKB"], "20.72KB")
        self.assertEqual(data["freeVolatileBytes"], 5098)
        self.assertIsNone(data["totalBytesApprox"])
        self.assertIn("无法计算", describe_capacity(data, "zh"))

    def test_profile_sizes_sum_to_approximate_total(self):
        profiles = [
            {"iccid": "8901", "profileNickname": "A", "profileSize": 20480},
            {"iccid": "8902", "profileNickname": "B", "profileSize": 40960},
            {"iccid": "8903", "profileNickname": "C"},   # 卡未报告 profileSize
        ]
        data = capacity_data(self.INFO, profiles)
        self.assertEqual(data["installedBytes"], 61440)
        self.assertEqual(data["totalBytesApprox"], 61440 + 21214)
        self.assertEqual(data["profilesWithSize"], 2)
        self.assertIsNone(data["profiles"][2]["profileSize"])
        self.assertEqual(data["usedPercentApprox"], round(61440 * 100 / (61440 + 21214), 1))
        self.assertIn("近似总容量", describe_capacity(data, "zh"))
        self.assertIn("Approx. total capacity", describe_capacity(data, "en"))

    def test_capacity_requires_ext_card_resource(self):
        with self.assertRaisesRegex(ValueError, "extCardResource"):
            capacity_data({"svn": "2.2.2"})

    def test_euicc_info_explanation_shows_official_kb(self):
        text = describe_euicc_info(
            {"extCardResource": {"freeNonVolatileMemory": 20856}}, "zh")
        self.assertIn("20.37KB", text)


class APITests(unittest.IsolatedAsyncioTestCase):
    async def test_enable_already_enabled_is_success(self):
        raw = bytes.fromhex("BF3103800102")
        sim = BeeSim(euicc(response_sequence(raw)))
        self.assertTrue(await sim.enable_profile("8901"))

    async def test_filtered_profiles_and_extended_fields(self):
        profile = tlv(0xE3, tlv(0x5A, bytes.fromhex("9810")), tlv([0x9F, 0x70], b"\x01"),
                        tlv(0x93, b"\x02"), tlv(0x94, b"icon"), tlv(0x99, b"\x01"))
        raw = tlv([0xBF, 0x2D], tlv(0xA0, profile))
        sim = BeeSim(euicc(response_sequence(raw)))
        profiles = await sim.get_profiles("5C075A9F7090919295")
        self.assertEqual(profiles[0]["iccid"], "8901")
        self.assertEqual(profiles[0]["iconType"], "png")
        self.assertEqual(profiles[0]["profilePolicyRules"], "01")
        self.assertEqual(sim.e.t.commands[4][5:], bytes.fromhex("BF2D095C075A9F7090919295"))

    async def test_info_negotiates_protocol(self):
        raw = bytes.fromhex("BF20058203020300")
        sim = BeeSim(euicc(response_sequence(raw)))
        self.assertEqual((await sim.get_euicc_info1())["svn"], "2.3.0")
        self.assertEqual(sim.protocol, "gsma/rsp/v2.3.0")

    async def test_confirmation_hash_uses_signed_transaction(self):
        signed = tlv(0x30, tlv(0x80, b"\x01\x02"), tlv(1, b"\xff"))
        sim = BeeSim(euicc([]))
        with self.assertRaisesRegex(ValueError, "Confirmation"):
            await sim.prepare_download(signed, b"", b"")
        sim._read = AsyncMock(return_value=bytes.fromhex("BF2102A000"))
        await sim.prepare_download(signed, b"", b"", "1234")
        import hashlib
        expected = hashlib.sha256(hashlib.sha256(b"1234").digest() + b"\x01\x02").digest()
        self.assertIn(tlv(4, expected), sim._read.call_args.args[0])

    async def test_notification_delivery_failure_does_not_delete(self):
        metadata = tlv([0xBF, 0x2F], tlv(0x80, b"\x01"), tlv(0x0C, b"rsp.example.com"))
        item = tlv(0x30, metadata)
        raw = tlv([0xBF, 0x2B], tlv(0xA0, item))
        sim = BeeSim(euicc([]))
        sim.retrieve_notification = AsyncMock(return_value=raw)
        sim.remove_notification = AsyncMock()
        gateway = SimpleNamespace(execute=AsyncMock(side_effect=RuntimeError("offline")))
        with self.assertRaisesRegex(RuntimeError, "offline"):
            await sim.send_notification("01", gateway)
        sim.remove_notification.assert_not_awaited()
        gateway.execute.side_effect = None
        await sim.send_notification("01", gateway)
        sim.remove_notification.assert_awaited_once_with("01")
        import base64
        self.assertEqual(gateway.execute.call_args.args[3]["pendingNotification"], base64.b64encode(item).decode())

    async def test_send_notification_deletes_requested_sequence(self):
        metadata = tlv([0xBF, 0x2F], tlv(0x80, b"\x09"), tlv(0x0C, b"rsp.example.com"))
        item = tlv(0x30, metadata)
        raw = tlv([0xBF, 0x2B], tlv(0xA0, item))
        sim = BeeSim(euicc([]))
        sim.retrieve_notification = AsyncMock(return_value=raw)
        sim.remove_notification = AsyncMock()
        gateway = SimpleNamespace(execute=AsyncMock(return_value={}))
        await sim.send_notification("01", gateway)
        sim.remove_notification.assert_awaited_once_with("01")

    async def test_remove_notification_not_found_result(self):
        sim = BeeSim(euicc(response_sequence(bytes.fromhex("BF3003800101"))))
        with self.assertRaisesRegex(RuntimeError, "Notification not found"):
            await sim.remove_notification("01")

    async def test_delete_notification_is_kept_after_successful_send(self):
        metadata = tlv([0xBF, 0x2F], tlv(0x80, b"\x01"),
                         tlv(0x0C, b"rsp.example.com"), tlv(0x81, bytes.fromhex("0410")))
        item = tlv(0x30, metadata)
        raw = tlv([0xBF, 0x2B], tlv(0xA0, item))
        sim = BeeSim(euicc([]))
        sim.retrieve_notification = AsyncMock(return_value=raw)
        sim.remove_notification = AsyncMock()
        gateway = SimpleNamespace(execute=AsyncMock(return_value={}))
        result = await sim.send_notification("01", gateway)
        self.assertEqual(result["profileManagementOperation"], "DELETE")
        sim.remove_notification.assert_not_awaited()

    async def test_firmware_headers_and_failure_stop(self):
        e = euicc(["10000001", "10000001", "9000"])
        await BeeSim(e).download_firmware(["F001", "F200"], log=lambda _: None)
        self.assertEqual(e.t.commands[:2], [bytes.fromhex("00020001F001"), bytes.fromhex("00020002F200")])
        self.assertEqual(e.t.commands[-1], bytes.fromhex("A03F000000"))
        e = euicc(["00000000"])
        with self.assertRaises(RuntimeError):
            await BeeSim(e).download_firmware(["F001"], log=lambda _: None)
        self.assertEqual(len(e.t.commands), 1)
        self.assertEqual(e.delay_over_counter, 0)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_immediate_notification_and_response_write_mode(self):
        class Client:
            async def write_gatt_char(client, uuid, packet, response):
                self.assertTrue(response)
                self.assertEqual(packet, bytes.fromhex("01010070000100"))
                transport._on_notify(None, bytearray.fromhex("01019000"))
        transport = BeeSimTransport(Client(), "w", "n", write_with_response=True)
        self.assertEqual(await transport.send(bytes.fromhex("0070000100")), bytes.fromhex("9000"))

    async def test_fragment_reassembly_and_serialization(self):
        class Client:
            async def write_gatt_char(client, uuid, packet, response):
                await asyncio.sleep(0)
                if packet[0] == packet[1]:
                    transport._on_notify(None, bytearray.fromhex("0201AABB"))
                    transport._on_notify(None, bytearray.fromhex("0202CC9000"))
        transport = BeeSimTransport(Client(), "w", "n")
        self.assertEqual(await transport.send(b"a" * 20), bytes.fromhex("AABBCC9000"))
        results = await asyncio.gather(transport.send(b"a"), transport.send(b"b"))
        self.assertEqual(results, [bytes.fromhex("AABBCC9000")] * 2)

    async def test_timeout_requires_fresh_session(self):
        transport = BeeSimTransport(SimpleNamespace(write_gatt_char=AsyncMock()), "w", "n", timeout=0.01)
        with self.assertRaises(TimeoutError):
            await transport.send(b"a")
        with self.assertRaises(ConnectionError):
            await transport.send(b"b")

    async def test_out_of_order_frame_rejected(self):
        class Client:
            async def write_gatt_char(client, *args, **kwargs):
                transport._on_notify(None, bytearray.fromhex("02029000"))
        transport = BeeSimTransport(Client(), "w", "n")
        with self.assertRaisesRegex(RuntimeError, "Out-of-order"):
            await transport.send(b"a")

    async def test_disconnect_interrupts_pending_response(self):
        class Client:
            async def write_gatt_char(client, *args, **kwargs):
                transport.disconnected(client)
        transport = BeeSimTransport(Client(), "w", "n")
        with self.assertRaises(ConnectionError):
            await transport.send(b"a")

    async def test_connect_prefers_no_response_and_cleans_failure(self):
        chars = [SimpleNamespace(uuid="write", properties=["write"]),
                 SimpleNamespace(uuid="write-nr", properties=["write-without-response"]),
                 SimpleNamespace(uuid="notify", properties=["notify"])]
        client = SimpleNamespace(connect=AsyncMock(), disconnect=AsyncMock(), start_notify=AsyncMock(),
                                 services=[SimpleNamespace(uuid=SERVICE_UUID, characteristics=chars)])
        with patch("beesim_transport.BleakClient", return_value=client):
            _, _, e = await connect("test")
        self.assertEqual(e.t.write_uuid, "write-nr")
        self.assertFalse(e.t.write_with_response)
        client.services = []
        with patch("beesim_transport.BleakClient", return_value=client), self.assertRaises(RuntimeError):
            await connect("test")
        client.disconnect.assert_awaited_once()
