import subprocess
import sys
import unittest
from unittest.mock import patch

from beesim import main


class CLITests(unittest.TestCase):
    def test_help_and_firmware_write_confirmation(self):
        result = subprocess.run([sys.executable, "beesim.py", "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--rsp-transport", result.stdout)
        self.assertIn("notification-send", result.stdout)
        result = subprocess.run([sys.executable, "beesim.py", "firmware-write", "missing.txt"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --yes", result.stderr)

    def test_tui_language_both_argument_positions(self):
        for arguments in (["beesim.py"], ["beesim.py", "--lang", "zh"], ["beesim.py", "tui", "--lang", "en"]):
            with self.subTest(arguments=arguments), patch.object(sys, "argv", arguments), patch("beesim.run_tui") as run:
                main()
                expected = None if len(arguments) == 1 else arguments[-1]
                self.assertEqual(run.call_args.args[1], expected)
