import unittest

from intelligence import live_sources


KEV = {
    "catalogVersion": "2026.10.04",
    "dateReleased": "2026-10-04T18:52:56Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-12345", "vendorProject": "Acme", "product": "Agent Hub",
            "vulnerabilityName": "Acme Agent Hub authorization flaw", "dateAdded": "2026-10-03",
            "shortDescription": "A role boundary can be bypassed.", "requiredAction": "Apply the update.",
            "dueDate": "2026-10-20", "knownRansomwareCampaignUse": "Unknown",
            "notes": "https://vendor.example/advisory", "cwes": ["CWE-862"],
        },
        {
            "cveID": "CVE-2026-99999", "vendorProject": "Other", "product": "Old Product",
            "vulnerabilityName": "Older issue", "dateAdded": "2026-09-01",
            "shortDescription": "Older entry.", "requiredAction": "Update.",
            "dueDate": "2026-09-20", "knownRansomwareCampaignUse": "Known",
            "notes": "", "cwes": None,
        },
    ],
}

CVE = {
    "cveMetadata": {
        "cveId": "CVE-2026-12345", "state": "PUBLISHED",
        "datePublished": "2026-10-02T00:00:00Z", "dateUpdated": "2026-10-03T00:00:00Z",
    },
    "containers": {"cna": {
        "title": "Acme Agent Hub authorization flaw",
        "descriptions": [{"lang": "en", "value": "A role boundary can be bypassed."}],
        "affected": [{"vendor": "Acme", "product": "Agent Hub", "defaultStatus": "unaffected",
                      "versions": [{"version": "1.0", "status": "affected"}]}],
        "problemTypes": [{"descriptions": [{"lang": "en", "description": "CWE-862"}]}],
        "references": [
            {"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]},
            {"url": "http://insecure.example/ignored", "tags": ["third-party-advisory"]},
        ],
    }},
}


def fake_fetch(url):
    if url == live_sources.CISA_KEV_URL:
        return KEV
    if url == live_sources.CVE_API_ROOT + "CVE-2026-12345":
        return CVE
    raise AssertionError(url)


class LiveSourcesTests(unittest.TestCase):
    def test_kev_search_filters_locally_by_term_and_date(self):
        result = live_sources.search_kev("Agent Hub", added_since="2026-10-01", fetch=fake_fetch)
        self.assertEqual(result["catalog_version"], "2026.10.04")
        self.assertEqual([item["cve_id"] for item in result["matches"]], ["CVE-2026-12345"])
        self.assertIn("does not authorize testing", result["interpretation"])

    def test_exact_cve_combines_cve_list_and_kev(self):
        result = live_sources.verify_cve("cve-2026-12345", fetch=fake_fetch)
        self.assertEqual(result["state"], "PUBLISHED")
        self.assertEqual(result["affected"][0]["product"], "Agent Hub")
        self.assertEqual(result["problem_types"], ["CWE-862"])
        self.assertEqual(result["references"], [
            {"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]},
        ])
        self.assertEqual(result["cisa_kev"]["date_added"], "2026-10-03")

    def test_invalid_inputs_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "CVE-YYYY"):
            live_sources.verify_cve("not-a-cve", fetch=fake_fetch)
        with self.assertRaisesRegex(ValueError, "YYYY-MM-DD"):
            live_sources.search_kev(added_since="yesterday", fetch=fake_fetch)


if __name__ == "__main__":
    unittest.main()
