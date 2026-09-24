import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "nas_installer", Path(__file__).resolve().parents[1] / "infra/deploy/install_nas.py"
)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_preserves_existing_shells_and_only_matches_same_uid(self):
        before = [
            "xiaoxiao:x:1030:100:old:/home/xiaoxiao:/bin/sh",
            "admin:x:1024:100:admin:/home/admin:/bin/bash",
        ]
        after = [
            "xiaoxiao:x:1030:100:updated:/home/xiaoxiao:/sbin/nologin",
            "admin:x:2024:100:new:/home/admin:/sbin/nologin",
            "deploy-ass:x:1040:100:deploy:/home/deploy:/sbin/nologin",
        ]
        restored = installer.restore_existing_shells(before, after)
        self.assertEqual(restored[0], "xiaoxiao:x:1030:100:updated:/home/xiaoxiao:/bin/sh")
        self.assertEqual(restored[1:], after[1:])

    def test_restores_management_access_even_when_account_command_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            passwd = root / "passwd"
            original = "xiaoxiao:x:1030:100::/home/xiaoxiao:/bin/sh\n"
            passwd.write_text(original)

            def failed(*args, **kwargs):
                passwd.write_text(original.replace("/bin/sh", "/sbin/nologin"))
                return subprocess.CompletedProcess(args, 1)

            with (
                patch.object(installer, "ROOT", root),
                patch.object(installer.subprocess, "run", side_effect=failed),
                patch.object(installer.os, "fchown"),
                self.assertRaisesRegex(RuntimeError, "DSM account creation failed"),
            ):
                installer.create_account("deploy-ass", "ass", passwd)
            self.assertEqual(passwd.read_text(), original)
            self.assertEqual(
                (root / "admin-backups/passwd-before-deploy-ass").read_text(), original
            )


if __name__ == "__main__":
    unittest.main()
