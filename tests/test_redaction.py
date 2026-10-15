import unittest

from scanner.redaction import fingerprint_secret, is_placeholder, mask_secret


class RedactionTests(unittest.TestCase):
    def test_mask_keeps_only_short_edges(self):
        value = "sk_live_1234567890abcdef"
        masked = mask_secret(value)
        self.assertEqual(masked, "sk_l...cdef")
        self.assertNotIn("1234567890", masked)

    def test_short_values_are_not_revealed(self):
        self.assertEqual(mask_secret("123456"), "12...56")

    def test_placeholder_detection(self):
        for value in ("${API_KEY}", "YOUR_API_KEY", "********", "redacted", "example-token"):
            with self.subTest(value=value):
                self.assertTrue(is_placeholder(value))

    def test_fingerprint_is_keyed_and_stable(self):
        first = fingerprint_secret("secret-value", b"key-a")
        second = fingerprint_secret("secret-value", b"key-a")
        other = fingerprint_secret("secret-value", b"key-b")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertEqual(len(first), 64)


if __name__ == "__main__":
    unittest.main()
