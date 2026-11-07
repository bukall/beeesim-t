import base64
import hashlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from beesim_web import WebAPI, _client_secret

from beesim_download import download_profile
from beesim_euicc import Euicc
from beesim_tlv import tlv

class WebTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.requests = []
        self.responses = []

        def opener(request, **kwargs):
            self.requests.append(request)
            value = self.responses.pop(0) if self.responses else {"status": 200, "data": {}}
            return io.BytesIO(json.dumps(value).encode())
        self.client = WebAPI(opener=opener, clock=lambda: 123.456)

    async def test_proxy_request_contract(self):
        self.responses.append({"status": 200, "data": {"transactionId": "ABC"}})
        value = await self.client.execute("initiateAuthentication", "rsp.example.com", "gsma/rsp/v2.2.2",
                                          {"euiccChallenge": "AQ==", "euiccInfo1": "Ag=="})
        self.assertEqual(value, {"transactionId": "ABC"})
        request = self.requests[0]
        self.assertEqual(request.full_url, "https://beeesim.com/fetch/v2/plugin/esim/rsp/es9plus/execute.do?action=initiateAuthentication")
        self.assertEqual(json.loads(request.data), {"euiccChallenge": "AQ==", "euiccInfo1": "Ag==",
                                                   "smdpAddress": "rsp.example.com", "protocol": "gsma/rsp/v2.2.2"})
        self.assertEqual(request.method, "POST")

    async def test_exact_signed_body_and_token(self):
        self.client.token = "test-token"
        with patch("beesim_web._client_secret", return_value="public-test"):
            await self.client.bind("1234")
        request = self.requests[0]
        self.assertEqual(request.data, b'{"eid":"1234"}')
        expected = hashlib.md5(base64.b64encode(b'action=bind{"eid":"1234"}test-token123456public-test')).hexdigest()
        self.assertEqual(request.get_header("B-sign"), expected)
        self.assertEqual(request.get_header("B-token"), "test-token")

    async def test_login_contract_and_all_http_families(self):
        self.responses.append({"status": 200, "data": {"nickname": "test"}, "token": "test-token"})
        with patch("beesim_web._client_secret", return_value="public-test"):
            await self.client.login("test@example.com", password="test-password")
            await self.client.devices()
            await self.client.email_vercode("test@example.com")
            await self.client.save_nickname("中文")
            await self.client.firmware_versions()
            await self.client.check_pe("rsp.example.com")
        self.assertEqual(json.loads(self.requests[0].data)["by"], "email-passwd")
        self.assertEqual(json.loads(self.requests[0].data)["password"], hashlib.md5(b"test-password").hexdigest())
        firmware = self.requests[4]
        self.assertIn("/fetch/v2/plugin/mall/firmware.do?", firmware.full_url)
        self.assertIsNotNone(firmware.get_header("X-sign"))
        self.assertEqual(len(self.requests), 6)

    async def test_server_error_and_unauthorized_do_not_echo_token(self):
        self.client.token = "private-test-token"
        self.responses.append({"status": 401, "msg": "private-test-token"})
        with self.assertRaises(RuntimeError) as error:
            await self.client.execute("handleNotification", "rsp.example.com", "gsma/rsp/v2.2.2", {})
        self.assertNotIn("private-test-token", str(error.exception))
        self.assertIsNone(self.client.token)

    def test_public_web_signing_constants_can_be_decoded(self):
        for kind in ("Mall", "BeeSIM"):
            value = _client_secret(kind)
            self.assertTrue(isinstance(value, str) and len(value) > 0)


def installation_result(success=True):
    metadata = tlv([0xBF, 0x2F], tlv(0x80, b"\x01"), tlv(0x0C, b"rsp.example.com"))
    final = tlv(0xA0) if success else tlv(0xA1, tlv(0x81, b"\x09"))
    return tlv([0xBF, 0x37], tlv([0xBF, 0x27], metadata, tlv(0xA2, final)))


class DownloadTests(unittest.IsolatedAsyncioTestCase):
    def make_download(self, *, upload_error=False, success=True):
        e = Euicc(SimpleNamespace(), delay_over_counter=0)
        e.init = AsyncMock()
        e.set_tx_power = AsyncMock()
        raw = installation_result(success)
        sim = SimpleNamespace(
            protocol="gsma/rsp/v2.2.2", get_euicc_challenge=AsyncMock(return_value=b"challenge"),
            get_euicc_info1=AsyncMock(return_value={"raw": "BF20058203020202"}),
            authenticate_server=AsyncMock(return_value=b"auth"), prepare_download=AsyncMock(return_value=b"prepare"),
            load_bound_profile_package=AsyncMock(return_value=raw), remove_notification=AsyncMock())
        encode = lambda value: base64.b64encode(value).decode()
        replies = [
            {"transactionId": "1234", "serverSigned1": encode(b"a"), "serverSignature1": encode(b"b"),
             "euiccCiPKIdToBeUsed": encode(b"c"), "serverCertificate": encode(b"d")},
            {"smdpSigned2": encode(b"e"), "smdpSignature2": encode(b"f"), "smdpCertificate": encode(b"g"),
             "profileMetadata": encode(tlv([0xBF, 0x25], tlv(0x5A, bytes.fromhex("9810"))))},
            {"boundProfilePackage": encode(b"package")},
            RuntimeError("offline") if upload_error else {},
        ]
        gateway = SimpleNamespace(execute=AsyncMock(side_effect=replies))
        return e, sim, gateway

    async def test_complete_download_includes_notification_and_power_restore(self):
        e, sim, gateway = self.make_download()
        result = await download_profile(sim, e, "rsp.example.com", "matching", gateway=gateway, log=lambda _: None)
        self.assertEqual(result["iccid"], "8901")
        self.assertEqual([c.args[0] for c in gateway.execute.call_args_list], [
            "initiateAuthentication", "authenticateClient", "getBoundProfilePackage", "handleNotification"])
        self.assertEqual(gateway.execute.call_args_list[0].args[2], "gsma/rsp/v2.2.2")
        sim.remove_notification.assert_awaited_once_with("01")
        self.assertEqual([c.args[0] for c in e.set_tx_power.call_args_list], [4, 1])

    async def test_upload_failure_preserves_notification(self):
        e, sim, gateway = self.make_download(upload_error=True)
        with self.assertRaisesRegex(RuntimeError, "notification pending"):
            await download_profile(sim, e, "rsp.example.com", gateway=gateway, log=lambda _: None)
        sim.remove_notification.assert_not_awaited()
        sim.load_bound_profile_package.assert_awaited_once()
        self.assertEqual(e.set_tx_power.call_args_list[-1].args, (1,))

    async def test_installation_error_is_reported_and_notification_not_deleted(self):
        e, sim, gateway = self.make_download(success=False)
        with self.assertRaisesRegex(RuntimeError, "Installation failed: 09"):
            await download_profile(sim, e, "rsp.example.com", gateway=gateway, log=lambda _: None)
        self.assertEqual(gateway.execute.call_args.args[0], "handleNotification")
        sim.remove_notification.assert_not_awaited()
