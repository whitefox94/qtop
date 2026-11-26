"""Parser and storage tests. No network: fixtures mirror each upstream format."""

import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import secfeed as sf  # noqa: E402

RSS = b"""<?xml version="1.0"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel><title>Example</title>
<item>
  <title>Fortinet patches actively exploited FortiOS flaw (CVE-2026-12345)</title>
  <link>https://example.com/fortinet</link>
  <description><![CDATA[<p>Attackers are <b>exploiting</b> cve-2026-12345.</p>
    <script>alert(1)</script>]]></description>
  <pubDate>Tue, 24 Nov 2026 10:00:00 +0000</pubDate>
</item>
<item>
  <title>Hostile entry</title>
  <link>javascript:alert(1)</link>
  <pubDate>Tue, 24 Nov 2026 10:00:00 +0000</pubDate>
</item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<entry>
  <title>New prompt injection attack against coding agents</title>
  <link rel="self" href="https://example.org/self.atom"/>
  <link rel="alternate" href="https://example.org/post"/>
  <id>tag:example.org,2026:1</id>
  <published>2026-11-20T08:30:00Z</published>
  <summary type="html">&lt;p&gt;Details.&lt;/p&gt;</summary>
</entry>
</feed>"""

NVD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2026-0001", "published": "2026-11-24T10:15:07.123",
             "vulnStatus": "Analyzed",
             "descriptions": [{"lang": "es", "value": "hola"},
                              {"lang": "en", "value": "Buffer overflow in Foo. More."}],
             "metrics": {"cvssMetricV31": [{"cvssData": {
                 "baseScore": 9.8,
                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
             "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"},
                                             {"lang": "en", "value": "NVD-CWE-Other"}]}],
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"vulnerable": True, "criteria": "cpe:2.3:a:foo:bar_baz:*:*:*:*:*:*:*:*"}]}]}],
             "references": [{"url": "https://foo.example/advisory"},
                            {"url": "javascript:alert(1)"}]}},
    {"cve": {"id": "CVE-2026-0002", "published": "2026-11-24T11:00:00.000",
             "vulnStatus": "Rejected", "descriptions": [], "metrics": {}}},
    {"cve": {"id": "CVE-2026-0003", "published": "2026-11-24T12:00:00.000",
             "descriptions": [{"lang": "en", "value": "Unscored issue"}], "metrics": {}}},
]}

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Foo", "product": "Bar",
     "vulnerabilityName": "Foo Bar Overflow", "dateAdded": "2026-11-25",
     "shortDescription": "Bad.", "knownRansomwareCampaignUse": "Known",
     "requiredAction": "Apply mitigations per vendor instructions.",
     "dueDate": "2026-12-16", "notes": "https://foo.example/kb ; https://nvd.nist.gov/x"},
    {"cveID": "CVE-2019-0708", "vendorProject": "Microsoft", "product": "RDP",
     "vulnerabilityName": "BlueKeep", "dateAdded": "2021-11-03",
     "shortDescription": "Old.", "knownRansomwareCampaignUse": "Unknown"},
]}


class Parsers(unittest.TestCase):
    def test_rss(self):
        items = sf.parse_feed(RSS, "Example", "news")
        self.assertEqual(len(items), 1, "javascript: link must be dropped")
        i = items[0]
        self.assertEqual(i["url"], "https://example.com/fortinet")
        self.assertEqual(i["cves"], ["CVE-2026-12345"])
        self.assertIn("exploited", i["tags"])
        self.assertNotIn("<", i["summary"])
        self.assertNotIn("alert", i["summary"])
        self.assertEqual(i["published"], "2026-11-24T10:00:00Z")

    def test_atom_prefers_alternate_link_and_tags_ai(self):
        (i,) = sf.parse_feed(ATOM, "Blog", "news")
        self.assertEqual(i["url"], "https://example.org/post")
        self.assertIn("ai", i["tags"])
        self.assertEqual(i["summary"], "Details.")

    def test_nvd(self):
        items = sf.parse_nvd(NVD)
        self.assertEqual([i["cves"][0] for i in items], ["CVE-2026-0001", "CVE-2026-0003"])
        self.assertEqual(items[0]["severity"], 9.8)
        self.assertIsNone(items[1]["severity"])
        self.assertEqual(items[0]["title"], "CVE-2026-0001 — Buffer overflow in Foo")
        self.assertEqual(items[0]["published"], "2026-11-24T10:15:07Z")
        d = items[0]["details"]
        self.assertEqual(d["vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(d["cwes"], ["CWE-787"])
        self.assertEqual(d["products"], ["foo bar baz"])
        self.assertEqual(d["references"], ["https://foo.example/advisory"])
        self.assertEqual(items[1]["details"], {"description": "Unscored issue"})

    def test_kev(self):
        since = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
        ids, items = sf.parse_kev(KEV, since)
        self.assertEqual(ids, ["CVE-2026-0001", "CVE-2019-0708"])
        self.assertEqual(len(items), 1)
        self.assertLessEqual({"kev", "exploited", "ransomware"}, set(items[0]["tags"]))
        self.assertEqual(items[0]["details"]["due_date"], "2026-12-16")
        self.assertEqual(len(items[0]["details"]["references"]), 2)

    def test_ghsa(self):
        (i,) = sf.parse_ghsa([{
            "ghsa_id": "GHSA-xxxx", "cve_id": "CVE-2026-0009", "summary": "RCE in pkg",
            "html_url": "https://github.com/advisories/GHSA-xxxx", "description": "d",
            "severity": "high", "cvss": {"score": None},
            "published_at": "2026-11-23T00:00:00Z",
            "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "pkg"}}]}])
        self.assertEqual(i["severity"], 8.0)
        self.assertEqual(i["cves"], ["CVE-2026-0009"])
        self.assertTrue(i["summary"].startswith("Packages: pkg."))

    def test_github_search(self):
        (i,) = sf.parse_github_search({"items": [{
            "full_name": "someone/cve-2026-0001-poc", "stargazers_count": 12,
            "html_url": "https://github.com/someone/cve-2026-0001-poc",
            "description": None, "created_at": "2026-11-25T00:00:00Z"}]},
            "GitHub PoCs", "cve", ["poc"])
        self.assertEqual(i["cves"], ["CVE-2026-0001"])
        self.assertIn("poc", i["tags"])

    def test_hn_falls_back_to_discussion_link(self):
        (i,) = sf.parse_hn({"hits": [{"objectID": "42", "title": "Ask HN: jailbreaks?",
                                      "url": None, "created_at": "2026-11-25T00:00:00Z",
                                      "points": 10, "num_comments": 3}]}, "HN", "ai")
        self.assertEqual(i["url"], "https://news.ycombinator.com/item?id=42")

    def test_x_and_threads(self):
        (x,) = sf.parse_x({"data": [{"id": "1", "text": "CVE-2026-0001 PoC out",
                                     "author_id": "9", "created_at": "2026-11-25T00:00:00.000Z"}],
                           "includes": {"users": [{"id": "9", "username": "researcher"}]}},
                          "X", "social")
        self.assertEqual(x["url"], "https://x.com/researcher/status/1")
        (t,) = sf.parse_threads({"data": [{"id": "2", "text": "prompt injection demo",
                                           "permalink": "https://www.threads.net/@a/post/b",
                                           "timestamp": "2026-11-25T00:00:00+0000",
                                           "username": "a"}]}, "Threads", "social")
        self.assertIn("ai", t["tags"])
        self.assertEqual(t["published"], "2026-11-25T00:00:00Z")

    def test_github_releases_skip_prereleases(self):
        items = sf.parse_github_releases([
            {"tag_name": "v3.4.0", "name": "v3.4.0", "html_url": "https://github.com/o/tool/releases/tag/v3.4.0",
             "body": "## Changes\n* fix", "published_at": "2026-11-20T00:00:00Z"},
            {"tag_name": "v3.5.0-rc1", "prerelease": True,
             "html_url": "https://github.com/o/tool/releases/tag/v3.5.0-rc1",
             "published_at": "2026-11-21T00:00:00Z"}], "o/tool", "Tool releases", "tools")
        self.assertEqual([i["title"] for i in items], ["tool v3.4.0"])
        self.assertIn("release", items[0]["tags"])

    def test_epss(self):
        got = sf.parse_epss({"data": [
            {"cve": "CVE-2024-3094", "epss": "0.308320000", "percentile": "0.986600000"},
            {"cve": "CVE-2000-0001", "epss": "n/a", "percentile": "0"}]})
        self.assertEqual(got, {"CVE-2024-3094": (0.30832, 0.9866)})

    def test_alerts_match_and_format(self):
        kev = sf.make_item("CISA KEV", "cve", "CVE-2026-0001 — Foo", "https://e.com/k", tags=["kev"])
        hit = sf.make_item("News", "news", "Fortinet patches FortiOS", "https://e.com/f")
        miss = sf.make_item("News", "news", "Unrelated", "https://e.com/u")
        cfg = {"kev": True, "keywords": ["fortinet"], "max_per_refresh": 1}
        self.assertEqual(sf.alert_matches(kev, cfg), "Known exploited")
        self.assertEqual(sf.alert_matches(hit, cfg), "Watchlist: fortinet")
        self.assertIsNone(sf.alert_matches(miss, cfg))
        sent = []
        os.environ.pop("SECFEED_ALERT_URL", None)
        n = sf.send_alerts([kev, hit, miss], dict(cfg, url="https://ntfy.sh/t"),
                           post=lambda u, b, h: sent.append((u, b, h)))
        self.assertEqual(n, 2)
        self.assertEqual(len(sent), 2, "one alert plus one overflow notice")
        self.assertEqual(sent[0][2]["Click"], "https://e.com/k")
        self.assertIn(b"1 more", sent[1][1])
        sent.clear()
        sf.send_alerts([kev], dict(cfg, url="https://discord.com/api/webhooks/1/x"),
                       post=lambda u, b, h: sent.append((u, b, h)))
        self.assertIn("CVE-2026-0001", __import__("json").loads(sent[0][1])["content"])

    def test_future_dates_are_clamped(self):
        i = sf.make_item("s", "news", "t", "https://e.com/x",
                         published=sf.utcnow() + dt.timedelta(days=400))
        self.assertLessEqual(sf.parse_date(i["published"]), sf.utcnow())


class Classify(unittest.TestCase):
    def test_area_and_attack(self):
        areas, attacks = sf.classify("The Foo plugin for WordPress is vulnerable to SQL Injection")
        self.assertEqual((areas, attacks), (["WordPress & CMS"], ["SQL injection"]))
        areas, attacks = sf.classify("Fortinet FortiOS issue", ["CWE-787"])
        self.assertEqual((areas, attacks), (["Network & VPN"], ["Memory corruption"]))
        self.assertEqual(sf.classify("Something obscure"), (["Other"], ["Other"]))
        self.assertIn("AI & ML", sf.classify("Prompt injection in an MCP server")[0])


class Http(unittest.TestCase):
    def test_get_retries_transient_errors_but_not_4xx(self):
        import urllib.error
        calls = []

        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return b"ok"

        def flaky(req, timeout):
            calls.append(1)
            if len(calls) == 1:
                raise urllib.error.URLError("Temporary failure in name resolution")
            return Resp()

        def gone(req, timeout):
            calls.append(1)
            raise urllib.error.HTTPError(req.full_url, 404, "nope", {}, None)

        real_open, real_sleep = sf.urllib.request.urlopen, sf.time.sleep
        sf.time.sleep = lambda s: None
        try:
            sf.urllib.request.urlopen = flaky
            self.assertEqual(sf.http_get("https://e.com/"), b"ok")
            self.assertEqual(len(calls), 2)
            calls.clear()
            sf.urllib.request.urlopen = gone
            with self.assertRaises(urllib.error.HTTPError):
                sf.http_get("https://e.com/")
            self.assertEqual(len(calls), 1)
        finally:
            sf.urllib.request.urlopen, sf.time.sleep = real_open, real_sleep


class Storage(unittest.TestCase):
    def test_refresh_isolates_failures_and_flags_kev(self):
        recent = sf.iso(sf.utcnow() - dt.timedelta(hours=1))

        def good(src):
            return {"items": [sf.make_item("News", "news", "Story on CVE-2026-0001",
                                           "https://e.com/a", published=sf.parse_date(recent)),
                              sf.make_item("News", "news", "Old story", "https://e.com/old",
                                           published=sf.utcnow() - dt.timedelta(days=90))],
                    "kev": ["CVE-2026-0001"]}

        def bad(src):
            raise RuntimeError("boom")

        old = dict(sf.FETCHERS)
        sf.FETCHERS.update(good=good, bad=bad)
        try:
            db = sf.open_db(":memory:")
            cfg = {"retention_days": 30, "epss": False, "alerts": {"enabled": False}, "sources": [
                {"type": "good", "name": "News"}, {"type": "bad", "name": "Broken"},
                {"type": "x", "name": "X", "query": "q"},
                {"type": "good", "name": "Off", "enabled": False}]}
            os.environ.pop("X_BEARER_TOKEN", None)
            sf.refresh(db, cfg, log=lambda *_: None)
            sf.refresh(db, cfg, log=lambda *_: None)  # second run must not duplicate
            data = sf.export(db)
        finally:
            sf.FETCHERS.clear()
            sf.FETCHERS.update(old)
        self.assertEqual(len(data["items"]), 1, "old item pruned, no duplicates")
        self.assertIn("kev", data["items"][0]["tags"])
        self.assertEqual(data["items"][0]["details"], {})
        self.assertEqual(data["items"][0]["areas"], [], "only vulnerabilities are classified")
        states = {s["name"]: s["state"] for s in data["sources"]}
        self.assertEqual(states, {"News": "ok", "Broken": "error", "X": "skipped"})


if __name__ == "__main__":
    unittest.main()
