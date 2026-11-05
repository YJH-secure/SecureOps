"""Unit tests: no real network connections are made."""
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

from common.ssh_client import (
    SSHCollectionError,
    available_operations,
    run_readonly,
)


class TestSSHClient(unittest.TestCase):
    def setUp(self):
        self.options = {
            "target_id": "ubuntu-a",
            "host": "192.168.10.20",
            "username": "secureops-scan",
            "operation": "os_kernel",
        }

    @patch("common.ssh_client.subprocess.run")
    def test_success(self, runner):
        runner.return_value = CompletedProcess(args=[], returncode=0, stdout="Linux\n", stderr="")
        result = run_readonly(**self.options)
        self.assertEqual(result["stdout"], "Linux")
        self.assertEqual(result["exit_code"], 0)
        args = runner.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("BatchMode=yes", args)
        self.assertEqual(args[-1], "uname -s")

    def test_unknown_operation_rejected(self):
        with self.assertRaises(ValueError):
            run_readonly(**{**self.options, "operation": "rm_everything"})

    def test_invalid_host_rejected(self):
        with self.assertRaises(ValueError):
            run_readonly(**{**self.options, "host": "-oProxyCommand=bad"})

    @patch("common.ssh_client.subprocess.run")
    def test_remote_failure_is_error(self, runner):
        runner.return_value = CompletedProcess(args=[], returncode=255, stdout="", stderr="connection refused")
        with self.assertRaises(SSHCollectionError):
            run_readonly(**self.options)

    @patch("common.ssh_client.subprocess.run")
    def test_no_real_password_arguments(self, runner):
        runner.return_value = CompletedProcess(args=[], returncode=0, stdout="Linux", stderr="")
        run_readonly(**self.options)
        self.assertEqual(len(available_operations()), 4)
        self.assertNotIn("password", " ".join(runner.call_args.args[0]).lower())


if __name__ == "__main__":
    unittest.main()
