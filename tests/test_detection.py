import unittest

from scanner.detector import detect_candidates


class DetectionTests(unittest.TestCase):
    def test_provider_rule_identifies_stripe_and_line(self):
        text = "# config\nSTRIPE_KEY=sk_live_1234567890abcdefghijkl\n"
        candidates = detect_candidates(text, "config/.env", 60)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].provider, "Stripe")
        self.assertGreaterEqual(candidates[0].confidence, 60)
        self.assertEqual(candidates[0].line_number, 2)
        self.assertNotIn("1234567890", candidates[0].masked_preview)

    def test_provider_rule_identifies_aws_access_key(self):
        candidates = detect_candidates("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n", "x.env", 60)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].provider, "AWS")

    def test_generic_assignment_is_detected(self):
        candidates = detect_candidates("SERVICE_TOKEN = 'token-value-123456789'", "settings.py", 60)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].provider, "Unknown API credential")

    def test_masked_and_placeholder_examples_are_ignored(self):
        text = "KEY=YOUR_API_KEY\nTOKEN=***************\nVALUE=${SECRET}\n"
        self.assertEqual(detect_candidates(text, "README.md", 60), [])

    def test_safe_finding_does_not_contain_complete_candidate(self):
        text = "KEY=sk_live_1234567890abcdefghijkl\n"
        candidate = detect_candidates(text, "x.env", 60)[0]
        self.assertNotIn("1234567890", candidate.masked_preview)


if __name__ == "__main__":
    unittest.main()
