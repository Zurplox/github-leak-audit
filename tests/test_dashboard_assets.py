from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "scanner" / "dashboard_assets"
LAUNCHER = ROOT / "github-public-secret-scanner" / "run-dashboard.cmd"


class DashboardAssetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (ASSETS / "index.html").read_text(encoding="utf-8")
        cls.script = (ASSETS / "app.js").read_text(encoding="utf-8")
        cls.styles = (ASSETS / "styles.css").read_text(encoding="utf-8")
        cls.launcher = LAUNCHER.read_text(encoding="utf-8")

    def test_dashboard_has_operations_controls_and_findings_columns(self):
        for label in (
            "GitHub public secret scanner",
            "Scan controls",
            "Provider / API type",
            "Confidence",
            "Repository",
            "Exact file path",
            "Line",
            "Commit",
            "Masked preview",
            "Status",
            "Open source",
            "Provider distribution",
            "Confidence distribution",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.html)

    def test_script_polls_safe_api_and_supports_source_links(self):
        for path in (
            "/api/status",
            "/api/findings",
            "/api/summary",
            "/api/scans",
            "/api/scans/pause",
            "/api/scans/stop",
            "/api/disclosures/",
        ):
            with self.subTest(path=path):
                self.assertIn(path, self.script)
        self.assertIn("textContent", self.script)
        self.assertIn("href", self.script)
        self.assertNotIn("innerHTML", self.script)
        self.assertNotIn("localStorage", self.script)

    def test_ui_uses_masked_only_disclosure_language(self):
        combined = f"{self.html}\n{self.script}"
        self.assertIn("masked", combined.lower())
        self.assertIn("never displays complete credentials", combined.lower())
        self.assertNotIn('type="password"', self.html.lower())
        self.assertNotIn('name="token"', self.html.lower())

    def test_launcher_has_root_python_config_and_secret_safeguards(self):
        for text in (
            "%~dp0..",
            "config.example.toml",
            "config.toml",
            "SCANNER_FINGERPRINT_KEY",
            "3.11",
            "scanner.dashboard",
            "--open",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.launcher)
        self.assertIn("if not defined SCANNER_FINGERPRINT_KEY", self.launcher)
        self.assertNotIn("echo %SCANNER_FINGERPRINT_KEY%", self.launcher)


if __name__ == "__main__":
    unittest.main()
