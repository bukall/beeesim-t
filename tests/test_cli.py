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
