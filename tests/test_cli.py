import io
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from beesim import main

BEESIM_PY = str(Path(__file__).resolve().parent.parent / "beesim.py")


class CLITests(unittest.TestCase):
    def test_help_and_firmware_write_confirmation(self):
        result = subprocess.run([sys.executable, BEESIM_PY, "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--rsp-transport", result.stdout)
        self.assertIn("notification-send", result.stdout)
        result = subprocess.run([sys.executable, BEESIM_PY, "firmware-write", "missing.txt"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --yes", result.stderr)

    def test_tui_language_both_argument_positions(self):
        for arguments in (["beesim.py"], ["beesim.py", "--lang", "zh"], ["beesim.py", "tui", "--lang", "en"]):
            with self.subTest(arguments=arguments), patch.object(sys, "argv", arguments), patch("beesim.run_tui") as run:
                main()
                expected = None if len(arguments) == 1 else arguments[-1]
                self.assertEqual(run.call_args.args[1], expected)

    def test_tui_route_defaults_direct_and_web_is_proxy(self):
        from beesim_web import DirectRSP, WebAPI
        cases = [(["beesim.py"], DirectRSP),
                 (["beesim.py", "--rsp-transport", "web"], WebAPI),
                 (["beesim.py", "--rsp-transport", "direct"], DirectRSP)]
        for argv, expected in cases:
            with self.subTest(argv=argv), patch.object(sys, "argv", argv), patch("beesim.run_tui") as run:
                main()
            self.assertIsInstance(run.call_args.kwargs["gateway"], expected)


class CLIResetTests(unittest.IsolatedAsyncioTestCase):
    async def test_reset_failure_warns_on_stderr(self):
        from beesim import _run
        args = SimpleNamespace(command="reset", address=None, debug=False, timeout=30.0,
                               channel=1, store_max_lc=120, delay_over_counter=6, rsp_transport="web")
        client = SimpleNamespace(disconnect=AsyncMock())
        euicc = SimpleNamespace(reset=AsyncMock(return_value=False))
        with patch("beesim.connect", new=AsyncMock(return_value=(client, SimpleNamespace(), euicc))), \
                patch("sys.stderr", new=io.StringIO()) as err:
            with self.assertRaises(SystemExit) as ctx:   # 失败时非零退出码
                await _run(args)
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn("reset failed", err.getvalue())   # 显式复位失败要有 stderr 反馈
        euicc.reset.assert_awaited_once()

    async def test_firmware_reset_failure_exits_nonzero(self):
        from beesim import _run
        args = SimpleNamespace(command="firmware-write", file="dummy", resume=False,
                               address=None, debug=False, timeout=30.0, channel=1,
                               store_max_lc=120, delay_over_counter=6, rsp_transport="direct")
        client = SimpleNamespace(disconnect=AsyncMock())
        euicc = SimpleNamespace(check_upgrading=AsyncMock(
            return_value={"crc": "ABCD", "totalRows": 1, "currentRow": 0}))
        sim = SimpleNamespace(download_firmware=AsyncMock(return_value=False))
        with patch("beesim.connect", new=AsyncMock(return_value=(client, sim, euicc))), \
                patch("beesim.Path.read_text", return_value="dummy"), \
                patch("beesim.parse_firmware_text", return_value={"rows": ["F001"], "crc": "ABCD"}), \
                patch("sys.stderr", new=io.StringIO()) as err:
            with self.assertRaises(SystemExit) as ctx:
                await _run(args)
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn("reset not acknowledged", err.getvalue())

    async def test_download_explicit_empty_confirmation_clears_embedded(self):
        from beesim import _run
        args = SimpleNamespace(command="download", code="1$rsp.example.com$MATCH$$ABC",
                               confirm_code="", rsp_transport="direct", address=None, debug=False,
                               timeout=30.0, channel=1, store_max_lc=120, delay_over_counter=6)
        client = SimpleNamespace(disconnect=AsyncMock())
        with patch("beesim.connect", new=AsyncMock(return_value=(client, SimpleNamespace(), SimpleNamespace()))), \
                patch("beesim.download_profile", new=AsyncMock()) as dl:
            await _run(args)
        self.assertIsNone(dl.call_args.args[4])

    async def test_firmware_invalid_progress_raises(self):
        from beesim import _run
        args = SimpleNamespace(command="firmware-write", file="dummy", resume=False,
                               address=None, debug=False, timeout=30.0, channel=1,
                               store_max_lc=120, delay_over_counter=6, rsp_transport="direct")
        client = SimpleNamespace(disconnect=AsyncMock())
        euicc = SimpleNamespace(check_upgrading=AsyncMock(
            return_value={"crc": "ABCD", "totalRows": 2, "currentRow": 3}))
        with patch("beesim.connect", new=AsyncMock(return_value=(client, SimpleNamespace(), euicc))), \
                patch("beesim.Path.read_text", return_value="dummy"), \
                patch("beesim.parse_firmware_text", return_value={"rows": ["F001", "F200"], "crc": "ABCD"}):
            with self.assertRaisesRegex(ValueError, "Invalid firmware progress"):
                await _run(args)
