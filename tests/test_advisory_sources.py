import unittest

from intelligence import advisory_sources


class AdvisorySourcesTests(unittest.TestCase):
    def test_nvd_reduces_metrics_configurations_and_references(self):
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2026-12345", "published": "2026-10-01", "lastModified": "2026-10-02",
            "vulnStatus": "Analyzed",
            "metrics": {
                "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                                    "exploitabilityScore": 3.9, "impactScore": 5.9,
                                    "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N",
                                                 "baseScore": 9.8, "baseSeverity": "CRITICAL",
                                                 "attackVector": "NETWORK", "attackComplexity": "LOW",
                                                 "privilegesRequired": "NONE", "userInteraction": "NONE"}}],
                "ssvcV203": [{"ssvcData": {"timestamp": "2026-10-02",
                                             "options": [{"exploitation": "active"}]}}],
            },
            "weaknesses": [{"description": [{"value": "CWE-862"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                                             "criteria": "cpe:2.3:a:acme:hub:*",
                                                             "versionEndExcluding": "2.0"}]}]}],
            "references": [{"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]}],
        }}]}
        result = advisory_sources.nvd_details("CVE-2026-12345", fetch=lambda _url: payload)
        self.assertEqual(result["cvss"]["base_score"], 9.8)
        self.assertEqual(result["ssvc"][0]["options"]["exploitation"], "active")
        self.assertEqual(result["affected_cpes"][0]["versionEndExcluding"], "2.0")
        self.assertEqual(result["references"][0]["url"], "https://vendor.example/advisory")

    def test_exploitdb_searches_metadata_locally_and_never_returns_file_path(self):
        raw = (
            "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,"
            "codes,tags,aliases,screenshot_url,application_url,source_url\n"
            "42,exploits/python/42.py,Acme Hub auth bypass,2026-10-01,Researcher,webapps,python,443,"
            "2026-10-01,2026-10-02,1,CVE-2026-12345,Authentication Bypass,,,,"
            "https://vendor.example/advisory\n"
        ).encode()
        commits = [{"short_id": "abc123", "committed_date": "2026-10-02T00:00:00Z", "title": "DB update"}]
        result = advisory_sources.search_exploitdb(
            query="Acme Hub", limit=5,
            fetch_bytes=lambda _url, **_kwargs: raw,
            fetch_json=lambda _url: commits,
        )
        self.assertEqual(result["matches"][0]["exploitdb_id"], "42")
        self.assertTrue(result["matches"][0]["verified"])
        self.assertNotIn("file", result["matches"][0])
        self.assertNotIn("download", result["matches"][0])

    def test_osv_returns_package_ranges_without_advisory_details(self):
        payload = {"vulns": [{
            "id": "GHSA-test", "aliases": ["CVE-2026-12345"], "summary": "Acme issue",
            "published": "2026-10-01", "modified": "2026-10-02",
            "details": "Exploit recipe that must not be returned",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "acme", "purl": "pkg:pypi/acme"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
            "references": [{"type": "ADVISORY", "url": "https://vendor.example/advisory"}],
        }]}
        calls = []
        def fake_fetch(url, **kwargs):
            calls.append((url, kwargs))
            return payload
        result = advisory_sources.query_osv_package("PyPI", "acme", version="1.5", fetch=fake_fetch)
        self.assertEqual(calls[0][1]["body"]["version"], "1.5")
        self.assertEqual(result["advisories"][0]["affected"][0]["ranges"][0]["events"][1]["fixed"], "2.0")
        self.assertNotIn("details", result["advisories"][0])

    def test_multi_source_research_preserves_partial_failures(self):
        providers = {
            "good": lambda cve: {"id": cve},
            "down": lambda _cve: (_ for _ in ()).throw(ValueError("source unavailable")),
        }
        result = advisory_sources.research_cve("CVE-2026-12345", providers=providers)
        self.assertTrue(result["sources"]["good"]["ok"])
        self.assertFalse(result["sources"]["down"]["ok"])
        self.assertEqual(result["sources"]["down"]["error"], "source unavailable")


if __name__ == "__main__":
    unittest.main()
