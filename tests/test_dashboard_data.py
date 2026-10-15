import unittest

from scanner.dashboard_data import findings_payload, summary_payload
from scanner.models import FindingRecord


def finding(identity, provider, confidence, status, discovered_at):
    return FindingRecord(
        identity * 64, provider, confidence, "owner/repo", "main", "a" * 40,
        "config/.env", 2, "https://github.com/owner/repo/blob/" + "a" * 40 + "/config/.env#L2",
        "sk_l...x", "f" * 64, ("rule",), ("evidence",), discovered_at, status,
    )


class DashboardDataTests(unittest.TestCase):
    def test_findings_payload_is_paginated_and_has_no_candidate_value(self):
        records = [finding("a", "Stripe", 95, "open", "2026-10-14T08:00:00+00:00"),
                   finding("b", "AWS", 65, "reviewed", "2026-10-14T09:00:00+00:00")]
        payload = findings_payload(records, 2, 1, 2)
        self.assertEqual(payload["page"], 2)
        self.assertEqual(payload["pageSize"], 1)
        self.assertEqual(payload["totalItems"], 2)
        self.assertEqual(len(payload["data"]), 1)
        self.assertNotIn("value", payload["data"][0])

    def test_summary_payload_groups_safe_records(self):
        records = [finding("a", "Stripe", 95, "open", "2026-10-14T08:00:00+00:00"),
                   finding("b", "Stripe", 65, "reviewed", "2026-10-14T09:00:00+00:00"),
                   finding("c", "AWS", 35, "open", "2026-10-15T00:00:00+00:00")]
        payload = summary_payload(records)
        self.assertEqual(payload["totalFindings"], 3)
        self.assertEqual(payload["providers"], {"AWS": 1, "Stripe": 2})
        self.assertEqual(payload["statuses"], {"open": 2, "reviewed": 1})
        self.assertEqual(payload["confidence"], {"high": 1, "medium": 1, "low": 1})
        self.assertEqual(payload["byDate"], {"2026-10-14": 2, "2026-10-15": 1})

    def test_invalid_pagination_is_rejected(self):
        with self.assertRaises(ValueError):
            findings_payload([], 0, 10, 0)
        with self.assertRaises(ValueError):
            findings_payload([], 1, 101, 0)


if __name__ == "__main__":
    unittest.main()
