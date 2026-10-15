import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.config import Config, ConfigError


class ConfigTests(unittest.TestCase):
    def test_load_applies_conservative_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text("mode = 'hybrid'\n", encoding="utf-8")
            config = Config.load(path)

        self.assertEqual(config.mode, "hybrid")
        self.assertEqual(config.broad.max_concurrent_scans, 4)
        self.assertEqual(config.detection.confidence_threshold, 60)

    def test_invalid_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text("mode = 'everything'\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                Config.load(path)

    def test_fingerprint_key_must_come_from_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConfigError):
                Config.from_environment()

    def test_environment_values_are_not_trimmed_into_logs_or_config(self):
        with patch.dict(
            os.environ,
            {"SCANNER_FINGERPRINT_KEY": "local-test-key", "GITHUB_TOKEN": "token"},
            clear=True,
        ):
            secrets = Config.from_environment()

        self.assertEqual(secrets.fingerprint_key, b"local-test-key")
        self.assertEqual(secrets.github_token, "token")

    def test_continuous_broad_mode_has_a_bounded_poll_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text("[broad]\ncontinuous = true\npoll_interval_seconds = 12\n", encoding="utf-8")
            config = Config.load(path)

        self.assertTrue(config.broad.continuous)
        self.assertEqual(config.broad.poll_interval_seconds, 12)


if __name__ == "__main__":
    unittest.main()
