import os
import tempfile
import unittest

os.environ["LNSM_CONFIG_PATH"] = os.path.join(tempfile.gettempdir(), "lnsm_test_settings.json")

from sensor import is_whitelisted
from config import add_ignored_entry, load_settings, remove_ignored_entry, set_safe_mode


class SensorFilterTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        if os.path.exists(os.environ["LNSM_CONFIG_PATH"]):
            os.remove(os.environ["LNSM_CONFIG_PATH"])

    def test_private_networks_are_ignored(self):
        self.assertTrue(is_whitelisted("127.0.0.1"))
        self.assertTrue(is_whitelisted("192.168.1.25"))
        self.assertTrue(is_whitelisted("10.0.0.8"))
        self.assertTrue(is_whitelisted("172.16.0.5"))
        self.assertTrue(is_whitelisted("169.254.2.3"))

    def test_common_cloud_services_are_ignored(self):
        self.assertTrue(is_whitelisted("20.190.10.20"))
        self.assertTrue(is_whitelisted("52.96.123.45"))
        self.assertTrue(is_whitelisted("142.250.190.100"))

    def test_external_public_ip_is_not_ignored(self):
        self.assertFalse(is_whitelisted("8.8.8.8"))
        self.assertFalse(is_whitelisted("1.1.1.1"))


if __name__ == "__main__":
    unittest.main()
