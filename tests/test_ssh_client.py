import unittest
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from common.ssh_client import (
    run_readonly,
    available_operations,
    SSHCollectionError,
)

BASE = dict(
    target_id="linux2",
    host="203.0.113.10",
    username="secureops-scan",
    port=22,
)

class TestSSHClient(unittest.TestCase):

    def test_ssh01_is_allowed(self):
        self.assertIn("ssh01", available_operations())

    def test_invalid_operation_rejected(self):
        with self.assertRaises(ValueError):
            run_readonly(**BASE, operation="arbitrary_command")

    def test_invalid_host_rejected(self):
        args = dict(BASE, host="203.0.113.10;whoami")
        with self.assertRaises(ValueError):
            run_readonly(**args, operation="ssh01")

    @patch("common.ssh_client.subprocess.run")
    def test_ssh01_fixed_command(self, mock_run):
        mock_run.return_value = SimpleNamespace(
            returncode=0,
            stdout='{"check_id":"SSH-01"}\n',
        )

        result = run_readonly(**BASE, operation="ssh01")
        command = mock_run.call_args.args[0]

        self.assertEqual(
            command[-1],
            "sudo -n /usr/local/sbin/secureops-ssh01-read",
        )
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=yes", command)
        self.assertEqual(result["exit_code"], 0)

    @patch("common.ssh_client.subprocess.run")
    def test_ssh_failure(self, mock_run):
        mock_run.return_value = SimpleNamespace(
            returncode=255,
            stdout="",
        )

        with self.assertRaises(SSHCollectionError):
            run_readonly(**BASE, operation="ssh01")

    @patch("common.ssh_client.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="ssh",
            timeout=10,
        )

        with self.assertRaises(SSHCollectionError):
            run_readonly(**BASE, operation="ssh01")

if __name__ == "__main__":
    unittest.main()
