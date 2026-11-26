#!/usr/bin/env python3
"""secfeed - a personal security news feed.

Pulls CVEs, exploited-vulnerability alerts, security news and AI-security
(prompt injection / jailbreak) research from public sources into one local
SQLite database, and serves a single-page reader for it.

Standard library only, so there is nothing to install:

    python3 secfeed.py serve      # fetch on a timer and serve the reader
    python3 secfeed.py fetch      # fetch once (for cron)
    python3 secfeed.py build out  # write a static site (index.html + data.json)
"""

import argparse
import concurrent.futures
import datetime as dt
import email.utils
import hashlib
import html
import html.parser
import json
import os
import random
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
USER_AGENT = "secfeed/0.1 (personal feed reader)"
MAX_BODY = 8 * 1024 * 1024  # refuse responses larger than this
TIMEOUT = 40

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# Items from any source that match these get the "ai" tag, so an AI-security
# story from a general news feed also shows up under the AI tab.
AI_RE = re.compile(
    r"prompt[\s-]injection|jailbreak|\bLLMs?\b|large language model|"
    r"\bMCP\b|model context protocol|AI agents?|agentic|"
    r"\b(ChatGPT|Claude|Gemini|Copilot|OpenAI|Anthropic)\b|"
    r"adversarial (prompt|attack|example)|data poisoning|model (theft|extraction)",
    re.I,
)
EXPLOITED_RE = re.compile(
    r"exploited in the wild|actively exploited|under (active )?attack|"
    r"zero[\s-]day|0[\s-]day|in-the-wild exploitation",
    re.I,
)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def iso(d):
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(value):
    """Parse the date formats feeds actually use; return aware UTC or None."""
    if not value:
        return None
    value = value.strip()
    try:
        d = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
    if d.tzinfo is None:  # NVD and some feeds omit the zone; they mean UTC
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc)


class _TextExtractor(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def clean_text(value, limit=420):
    """Reduce feed HTML to plain text. The reader never renders feed HTML."""
    if not value:
        return ""
    p = _TextExtractor()
    try:
        p.feed(value)
        p.close()
        text = " ".join(p.parts)
    except Exception:
        text = re.sub(r"<[^>]+>", " ", value)
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    if len(text) > limit:
        text = text[: limit - 1].rsplit(" ", 1)[0] + "…"
    return text


def safe_url(url):
    """Only http(s) links are kept, so a feed cannot plant javascript: URLs."""
    if not url:
        return None
    url = url.strip()
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    return url if scheme in ("http", "https") else None


def http_get(url, headers=None, retries=2):
    """GET with retries for transient trouble (DNS hiccups, timeouts, 5xx).

    A refresh starts many lookups at once, which some home routers' DNS
    drops; a short pause and a second try is usually all it takes.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = resp.read(MAX_BODY + 1)
            break
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == retries:  # 4xx will not fix itself
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == retries:
                raise
        time.sleep(2 + 4 * attempt + random.random() * 2)
    if len(body) > MAX_BODY:
        raise ValueError("response larger than %d bytes" % MAX_BODY)
    return body


def http_post(url, body, headers=None):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        resp.read(MAX_BODY)


def http_json(url, headers=None):
    return json.loads(http_get(url, headers).decode("utf-8", "replace"))


def make_item(source, category, title, url, summary="", published=None,
              severity=None, tags=(), details=None):
    """Normalise one entry. Returns None if it has no usable link or title."""
    url = safe_url(url)
    title = clean_text(title, 300)
    if not url or not title:
        return None
    summary = clean_text(summary)
    now = utcnow()
    published = published or now
    if published > now:  # some feeds post-date entries; keep sorting sane
        published = now
    text = title + " " + summary
    cves = sorted({m.upper() for m in CVE_RE.findall(text + " " + url)})
    tags = set(tags)
    if category == "ai" or AI_RE.search(text):
        tags.add("ai")
    if EXPLOITED_RE.search(text):
        tags.add("exploited")
    return {
        "id": hashlib.sha1(url.encode()).hexdigest()[:20],
        "source": source,
        "category": category,
        "title": title,
        "url": url,
        "summary": summary,
        "published": iso(published),
        "severity": severity,
        "cves": cves,
        "tags": sorted(tags),
        # Extra facts for the reader's detail view; shape varies by source.
        "details": {k: v for k, v in (details or {}).items() if v},
    }


# --------------------------------------------------------------------------
# Parsers (pure functions: bytes/dicts in, items out - these are what the
# tests exercise, since they are where upstream format changes would bite)
# --------------------------------------------------------------------------

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _child_text(el, *names):
    for child in el:
        if _local(child.tag) in names and (child.text or "").strip():
            return child.text.strip()
    return ""


def parse_feed(body, source, category, tags=()):
    """Parse RSS 2.0, RSS 1.0 (RDF) or Atom."""
    root = ET.fromstring(body)
    items = []
    for el in root.iter():
        kind = _local(el.tag)
        if kind not in ("item", "entry"):
            continue
        link = _child_text(el, "link")
        if not link:  # Atom: <link href="..." rel="alternate"/>
            for child in el:
                if _local(child.tag) == "link" and child.get("href"):
                    if child.get("rel", "alternate") == "alternate":
                        link = child.get("href")
                        break
        if not link:
            link = _child_text(el, "guid", "id")
        item = make_item(
            source, category,
            _child_text(el, "title"), link,
            _child_text(el, "description", "summary", "content", "encoded"),
            parse_date(_child_text(el, "pubDate", "published", "updated", "date")),
            tags=tags,
        )
        if item:
            items.append(item)
    return items


def _nvd_score(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            score = (m.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def _nvd_vector(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            vector = (m.get("cvssData") or {}).get("vectorString")
            if vector:
                return vector
    return None


def _nvd_products(cve):
    """'vendor product' pairs from the CPE names NVD attaches, if any yet."""
    found = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = (m.get("criteria") or "").split(":")
                if len(parts) > 4 and m.get("vulnerable", True):
                    name = ("%s %s" % (parts[3], parts[4])).replace("_", " ")
                    if name not in found:
                        found.append(name)
    return found[:6]


def _http_urls(urls, limit=8):
    out = []
    for u in urls:
        u = safe_url(u)
        if u and u not in out:
            out.append(u)
    return out[:limit]


def parse_nvd(data):
    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve") or {}
        cid = cve.get("id")
        if not cid or cve.get("vulnStatus") == "Rejected":
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        item = make_item(
            "NVD", "cve", cid, "https://nvd.nist.gov/vuln/detail/" + cid, desc,
            parse_date(cve.get("published")), _nvd_score(cve.get("metrics") or {}),
            details={
                "description": clean_text(desc, 2500),
                "vector": _nvd_vector(cve.get("metrics") or {}),
                "cwes": sorted({d.get("value") for w in cve.get("weaknesses") or []
                                for d in w.get("description") or []
                                if (d.get("value") or "").startswith("CWE-")}),
                "products": _nvd_products(cve),
                "references": _http_urls(r.get("url") for r in cve.get("references") or []),
            },
        )
        if item:
            # Title is just the ID; put the first sentence in so it reads as news.
            first = desc.split(". ")[0].strip()
            item["title"] = "%s — %s" % (cid, clean_text(first, 140)) if first else cid
            items.append(item)
    return items


def parse_kev(data, since):
    """Returns (all KEV CVE ids, items for entries added on/after `since`)."""
    ids, items = [], []
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID")
        if not cid:
            continue
        ids.append(cid.upper())
        added = parse_date(v.get("dateAdded"))
        if not added or added < since:
            continue
        tags = ["kev", "exploited"]
        if (v.get("knownRansomwareCampaignUse") or "").lower() == "known":
            tags.append("ransomware")
        title = "%s — %s" % (cid, v.get("vulnerabilityName") or
                             "%s %s" % (v.get("vendorProject", ""), v.get("product", "")))
        item = make_item(
            "CISA KEV", "cve", title,
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            "?search_api_fulltext=" + cid,
            v.get("shortDescription", ""), added, tags=tags,
            details={
                "description": clean_text(v.get("shortDescription", ""), 2500),
                "products": ["%s %s" % (v.get("vendorProject", ""), v.get("product", ""))],
                "required_action": clean_text(v.get("requiredAction", ""), 600),
                "due_date": v.get("dueDate"),
                "cwes": [c for c in v.get("cwes") or [] if str(c).startswith("CWE-")],
                "references": _http_urls(re.findall(r"https?://[^\s;,]+", v.get("notes") or "")),
            },
        )
        if item:
            items.append(item)
    return ids, items


_GH_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5}


def parse_ghsa(data):
    items = []
    for a in data:
        score = (a.get("cvss") or {}).get("score")
        if not score:  # fall back to the bucket GitHub assigns
            score = _GH_SEVERITY.get((a.get("severity") or "").lower())
        ident = a.get("cve_id") or a.get("ghsa_id") or ""
        pkgs = sorted({(v.get("package") or {}).get("name", "")
                       for v in a.get("vulnerabilities") or []} - {""})
        summary = a.get("description") or ""
        if pkgs:
            summary = "Packages: %s. %s" % (", ".join(pkgs[:5]), summary)
        item = make_item(
            "GitHub Advisories", "cve",
            "%s — %s" % (ident, a.get("summary") or ""), a.get("html_url"),
            summary, parse_date(a.get("published_at")),
            float(score) if score else None,
            details={
                "description": clean_text(a.get("description") or "", 2500),
                "vector": (a.get("cvss") or {}).get("vector_string"),
                "cwes": [c.get("cwe_id") for c in a.get("cwes") or [] if c.get("cwe_id")],
                "products": pkgs[:6],
                "references": _http_urls(a.get("references") or []),
            },
        )
        if item:
            items.append(item)
    return items


def parse_github_search(data, source, category, tags=()):
    items = []
    for r in data.get("items", []):
        title = "%s ★%s" % (r.get("full_name", ""), r.get("stargazers_count", 0))
        item = make_item(source, category, title, r.get("html_url"),
                         r.get("description") or "",
                         parse_date(r.get("created_at")), tags=tags,
                         details={"stars": r.get("stargazers_count"),
                                  "language": r.get("language"),
                                  "last_push": r.get("pushed_at")})
        if item:
            # A repo named after a CVE should link to that CVE.
            item["cves"] = sorted(set(item["cves"]) |
                                  {m.upper() for m in CVE_RE.findall(r.get("full_name", ""))})
            items.append(item)
    return items


def parse_github_releases(data, repo, source, category):
    items = []
    for r in data:
        if r.get("draft") or r.get("prerelease"):
            continue
        tag = r.get("tag_name") or ""
        name = r.get("name") or ""
        title = "%s %s" % (repo.split("/")[-1], tag)
        if name and name != tag:
            title += " — " + name
        item = make_item(source, category, title, r.get("html_url"),
                         r.get("body") or "", parse_date(r.get("published_at")),
                         tags=["release"],
                         details={"description": clean_text(r.get("body") or "", 2500)})
        if item:
            items.append(item)
    return items


def parse_epss(data):
    """{CVE: (probability, percentile)} from FIRST's EPSS API."""
    out = {}
    for row in data.get("data") or []:
        try:
            out[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def parse_hn(data, source, category):
    items = []
    for h in data.get("hits", []):
        discussion = "https://news.ycombinator.com/item?id=%s" % h.get("objectID")
        item = make_item(
            source, category, h.get("title") or "", h.get("url") or discussion,
            "%s points · %s comments on Hacker News" % (h.get("points") or 0,
                                                         h.get("num_comments") or 0),
            parse_date(h.get("created_at")),
        )
        if item:
            items.append(item)
    return items


def parse_x(data, source, category):
    users = {u["id"]: u.get("username", "")
             for u in (data.get("includes") or {}).get("users", [])}
    items = []
    for t in data.get("data") or []:
        user = users.get(t.get("author_id"), "i")
        text = t.get("text", "")
        item = make_item(
            source, category, "@%s: %s" % (user, clean_text(text, 110)),
            "https://x.com/%s/status/%s" % (user, t.get("id")), text,
            parse_date(t.get("created_at")), tags=["social"],
        )
        if item:
            items.append(item)
    return items


def parse_threads(data, source, category):
    items = []
    for t in data.get("data") or []:
        text = t.get("text") or ""
        item = make_item(
            source, category,
            "@%s: %s" % (t.get("username", "threads"), clean_text(text, 110)),
            t.get("permalink"), text, parse_date(t.get("timestamp")),
            tags=["social"],
        )
        if item:
            items.append(item)
    return items


# --------------------------------------------------------------------------
# Fetchers (network). Each takes its config entry and returns
# {"items": [...], "kev": [...] (optional)}; raising marks the source failed
# without affecting the others.
# --------------------------------------------------------------------------

class Skipped(Exception):
    """Source is configured but cannot run (e.g. no API token)."""


def _gh_headers():
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        h["Authorization"] = "Bearer " + token
    return h


def fetch_rss(src):
    body = http_get(src["url"], {"Accept": "application/rss+xml, application/atom+xml, */*"})
    return {"items": parse_feed(body, src["name"], src.get("category", "news"),
                                src.get("tags", ()))}


def fetch_nvd(src):
    end = utcnow()
    start = end - dt.timedelta(days=src.get("days", 2))
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({
        "pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
        "resultsPerPage": 2000,
    })
    key = os.environ.get("NVD_API_KEY")
    items = parse_nvd(http_json(url, {"apiKey": key} if key else None))
    # NVD publishes several hundred CVEs a day. Keep the serious ones, plus
    # anything touching AI tooling whatever its score, so the feed stays readable.
    floor = src.get("min_severity", 7.0)
    return {"items": [i for i in items
                      if (i["severity"] or 0) >= floor or "ai" in i["tags"]]}


def fetch_kev(src):
    data = http_json(src.get(
        "url", "https://www.cisa.gov/sites/default/files/feeds/"
               "known_exploited_vulnerabilities.json"))
    since = utcnow() - dt.timedelta(days=src.get("days", 30))
    ids, items = parse_kev(data, since)
    return {"items": items, "kev": ids}


def fetch_ghsa(src):
    url = "https://api.github.com/advisories?" + urllib.parse.urlencode({
        "per_page": src.get("limit", 50), "sort": "published", "type": "reviewed"})
    return {"items": parse_ghsa(http_json(url, _gh_headers()))}


def fetch_github_search(src):
    now = utcnow()
    q = src["q"].format(year=now.year,
                        since=(now - dt.timedelta(days=src.get("days", 14))).strftime("%Y-%m-%d"))
    url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode({
        "q": q, "sort": src.get("sort", "updated"), "order": "desc",
        "per_page": src.get("limit", 25)})
    return {"items": parse_github_search(http_json(url, _gh_headers()), src["name"],
                                         src.get("category", "cve"), src.get("tags", ()))}


def fetch_github_releases(src):
    # One request per repo; a single slow or failed one should not cost the rest.
    items, errors = [], []
    for repo in src["repos"]:
        url = "https://api.github.com/repos/%s/releases?per_page=%d" % (
            urllib.parse.quote(repo), src.get("limit", 3))
        try:
            items += parse_github_releases(http_json(url, _gh_headers()), repo, src["name"],
                                           src.get("category", "tools"))
        except Exception as e:
            errors.append("%s: %s" % (repo, e))
    if errors and not items:
        raise RuntimeError("all %d repos failed, e.g. %s" % (len(errors), errors[0]))
    return {"items": items}


def fetch_hn(src):
    url = "https://hn.algolia.com/api/v1/search_by_date?" + urllib.parse.urlencode({
        "query": src["query"], "tags": "story", "hitsPerPage": src.get("limit", 20),
        "numericFilters": "points>%d" % src.get("min_points", 5)})
    return {"items": parse_hn(http_json(url), src["name"], src.get("category", "news"))}


def fetch_x(src):
    token = os.environ.get("X_BEARER_TOKEN")
    if not token:
        raise Skipped("set X_BEARER_TOKEN to enable (X API access is paid)")
    url = "https://api.x.com/2/tweets/search/recent?" + urllib.parse.urlencode({
        "query": src["query"], "max_results": max(10, min(100, src.get("limit", 25))),
        "tweet.fields": "created_at,author_id", "expansions": "author_id",
        "user.fields": "username"})
    data = http_json(url, {"Authorization": "Bearer " + token})
    return {"items": parse_x(data, src["name"], src.get("category", "social"))}


def fetch_threads(src):
    token = os.environ.get("THREADS_ACCESS_TOKEN")
    if not token:
        raise Skipped("set THREADS_ACCESS_TOKEN to enable (needs a Meta developer app "
                      "with the threads_keyword_search permission)")
    url = "https://graph.threads.net/v1.0/keyword_search?" + urllib.parse.urlencode({
        "q": src["query"], "search_type": "RECENT",
        "fields": "id,text,permalink,timestamp,username", "access_token": token})
    try:
        data = http_json(url)
    except urllib.error.HTTPError as e:
        # The token rides in the query string, so never echo the URL back.
        raise RuntimeError("Threads API returned HTTP %s" % e.code) from None
    return {"items": parse_threads(data, src["name"], src.get("category", "social"))}


FETCHERS = {
    "rss": fetch_rss, "nvd": fetch_nvd, "kev": fetch_kev, "ghsa": fetch_ghsa,
    "github_search": fetch_github_search, "github_releases": fetch_github_releases,
    "hn": fetch_hn,
    "x": fetch_x, "threads": fetch_threads,
}


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY, source TEXT, category TEXT, title TEXT, url TEXT,
    summary TEXT, published TEXT, severity REAL, cves TEXT, tags TEXT,
    fetched_at TEXT, details TEXT
);
CREATE INDEX IF NOT EXISTS items_published ON items(published DESC);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL, percentile REAL,
                                 checked_at TEXT);
CREATE TABLE IF NOT EXISTS source_status (
    name TEXT PRIMARY KEY, type TEXT, state TEXT, detail TEXT,
    count INTEGER, checked_at TEXT
);
"""


def open_db(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    # Databases created before the detail view lack this column.
    if "details" not in [r[1] for r in db.execute("PRAGMA table_info(items)")]:
        db.execute("ALTER TABLE items ADD COLUMN details TEXT")
    return db


def store_items(db, items):
    now = iso(utcnow())
    db.executemany(
        """INSERT INTO items VALUES (:id,:source,:category,:title,:url,:summary,
                                     :published,:severity,:cves,:tags,:fetched_at,:details)
           ON CONFLICT(id) DO UPDATE SET
             title=excluded.title, summary=excluded.summary,
             severity=COALESCE(excluded.severity, items.severity),
             cves=excluded.cves, tags=excluded.tags, details=excluded.details""",
        [dict(i, cves=",".join(i["cves"]), tags=",".join(i["tags"]), fetched_at=now,
              details=json.dumps(i.get("details") or {}))
         for i in items])


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def update_epss(db, limit=600):
    """Look up exploitation probability for recent CVEs we have not scored today.

    EPSS (from FIRST.org) estimates the chance a CVE is exploited in the next
    30 days. It is the best free signal for "which of these matters", since
    most high-CVSS bugs are never attacked.
    """
    since = iso(utcnow() - dt.timedelta(days=14))
    stale = iso(utcnow() - dt.timedelta(hours=20))
    fresh = {r[0] for r in db.execute("SELECT cve FROM epss WHERE checked_at > ?", (stale,))}
    wanted = []
    for (cves,) in db.execute("SELECT cves FROM items WHERE cves != '' AND published > ? "
                              "ORDER BY published DESC", (since,)):
        for c in cves.split(","):
            if c not in fresh and c not in wanted:
                wanted.append(c)
    wanted = wanted[:limit]
    now, found = iso(utcnow()), 0
    for i in range(0, len(wanted), 50):
        batch = wanted[i:i + 50]
        scores = parse_epss(http_json("https://api.first.org/data/v1/epss?cve=" + ",".join(batch)))
        for c in batch:  # record misses too, so brand-new CVEs are retried tomorrow, not every run
            score, pct = scores.get(c, (None, None))
            found += score is not None
            db.execute("INSERT OR REPLACE INTO epss VALUES (?,?,?,?)", (c, score, pct, now))
    return found


def alert_matches(item, alerts):
    """Why this item deserves a push notification, or None."""
    if alerts.get("kev", True) and "kev" in item["tags"]:
        return "Known exploited"
    if alerts.get("exploited", False) and "exploited" in item["tags"]:
        return "Exploited"
    text = (item["title"] + " " + item["summary"]).lower()
    for word in alerts.get("keywords") or []:
        if word.lower() in text:
            return "Watchlist: " + word
    return None


def send_alerts(items, alerts, post=None):
    """Push new matching items to ntfy, Discord or Slack. Returns how many matched."""
    post = post or http_post
    url = os.environ.get("SECFEED_ALERT_URL") or alerts.get("url")
    hits = [(why, i) for i in items for why in [alert_matches(i, alerts)] if why]
    if not url or not hits:
        return len(hits)
    cap = alerts.get("max_per_refresh", 8)
    for why, i in hits[:cap]:
        text = "%s\n%s\n%s" % (why, i["title"], i["url"])
        if "discord.com/api/webhooks" in url:
            post(url, json.dumps({"content": text}).encode(),
                 {"Content-Type": "application/json"})
        elif "hooks.slack.com" in url:
            post(url, json.dumps({"text": text}).encode(),
                 {"Content-Type": "application/json"})
        else:  # ntfy: plain-text body, metadata in headers
            post(url, ("%s\n%s" % (i["title"], i["url"])).encode(),
                 {"Title": "secfeed: " + why.encode("ascii", "ignore").decode(),
                  "Click": urllib.parse.quote(i["url"], safe=":/?&=#%+@,;~"),
                  "Tags": "rotating_light" if "xploited" in why else "eyes"})
    if len(hits) > cap:
        more = "secfeed: %d more new alerts, open the reader" % (len(hits) - cap)
        if "discord.com/api/webhooks" in url:
            post(url, json.dumps({"content": more}).encode(), {"Content-Type": "application/json"})
        elif "hooks.slack.com" in url:
            post(url, json.dumps({"text": more}).encode(), {"Content-Type": "application/json"})
        else:
            post(url, more.encode(), {"Title": "secfeed"})
    return len(hits)


def refresh(db, config, log=print):
    """Fetch every enabled source in parallel; store what came back."""
    sources = [s for s in config["sources"] if s.get("enabled", True)]

    def run(src):
        fetcher = FETCHERS.get(src["type"])
        if not fetcher:
            return src, "error", "unknown source type %r" % src["type"], {}
        try:
            return src, "ok", "", fetcher(src)
        except Skipped as e:
            return src, "skipped", str(e), {}
        except Exception as e:  # one bad feed must not sink the rest
            return src, "error", "%s: %s" % (type(e).__name__, e), {}

    total = 0
    # Alerts fire only for items never seen before, and never on the very
    # first run, when everything is "new" and would flood your phone.
    known = {r[0] for r in db.execute("SELECT id FROM items")}
    first_run, fresh = not known, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for src, state, detail, result in pool.map(run, sources):
            items = result.get("items", [])
            fresh += [i for i in items if i["id"] not in known]
            known.update(i["id"] for i in items)
            store_items(db, items)
            if "kev" in result:
                db.execute("DELETE FROM kev")
                db.executemany("INSERT OR IGNORE INTO kev VALUES (?)",
                               [(c,) for c in result["kev"]])
            db.execute("INSERT OR REPLACE INTO source_status VALUES (?,?,?,?,?,?)",
                       (src["name"], src["type"], state, detail, len(items), iso(utcnow())))
            total += len(items)
            log("  %-8s %-28s %s" % (state, src["name"],
                                     detail or "%d items" % len(items)))
    extras = []
    if config.get("epss", True):
        extras.append(("EPSS scores", "epss", lambda: "%d CVEs scored" % update_epss(db)))
    alerts = config.get("alerts") or {}
    if alerts.get("enabled", True) and not first_run:
        extras.append(("Alerts", "alerts", lambda: "%d sent" % send_alerts(fresh, alerts)
                       if os.environ.get("SECFEED_ALERT_URL") or alerts.get("url")
                       else "off: set SECFEED_ALERT_URL to get push alerts"))
    for name, kind, job in extras:
        try:
            state, detail = "ok", job()
        except Exception as e:
            state, detail = "error", "%s: %s" % (type(e).__name__, e)
        if detail.startswith("off:"):
            state = "skipped"
        db.execute("INSERT OR REPLACE INTO source_status VALUES (?,?,?,?,?,?)",
                   (name, kind, state, detail, 0, iso(utcnow())))
        log("  %-8s %-28s %s" % (state, name, detail))
    cutoff = iso(utcnow() - dt.timedelta(days=config.get("retention_days", 30)))
    db.execute("DELETE FROM items WHERE published < ?", (cutoff,))
    names = [s["name"] for s in config["sources"]] + [e[0] for e in extras]
    db.execute("DELETE FROM source_status WHERE name NOT IN (%s)" %
               ",".join("?" * len(names)), names)
    db.commit()
    return total


def export(db, limit=3000):
    """The one payload the reader needs; also what `build` writes to data.json."""
    kev = {r[0] for r in db.execute("SELECT cve FROM kev")}
    epss = {r[0]: (r[1], r[2]) for r in
            db.execute("SELECT cve, score, percentile FROM epss WHERE score IS NOT NULL")}
    items = []
    for r in db.execute("SELECT * FROM items ORDER BY published DESC LIMIT ?", (limit,)):
        cves = [c for c in r["cves"].split(",") if c]
        tags = [t for t in r["tags"].split(",") if t]
        if "kev" not in tags and any(c in kev for c in cves):
            tags.append("kev")  # e.g. a news story about a CVE that is in KEV
        items.append({
            "id": r["id"], "source": r["source"], "category": r["category"],
            "title": r["title"], "url": r["url"], "summary": r["summary"],
            "published": r["published"], "severity": r["severity"],
            "cves": cves, "tags": tags,
            "details": json.loads(r["details"] or "{}"),
            # Highest exploitation probability among the CVEs this item mentions.
            "epss": max((epss[c] for c in cves if c in epss), default=(None, None))[0],
            "epss_pct": max((epss[c] for c in cves if c in epss), default=(None, None))[1],
        })
    sources = [dict(r) for r in db.execute("SELECT * FROM source_status ORDER BY name")]
    return {"generated_at": iso(utcnow()), "items": items, "sources": sources}


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------

def serve(args, config):
    lock = threading.Lock()  # one refresh at a time
    stop = threading.Event()

    def do_refresh():
        if not lock.acquire(blocking=False):
            return False
        try:
            db = open_db(args.db)
            print("[%s] refreshing" % iso(utcnow()))
            refresh(db, config)
            db.close()
        finally:
            lock.release()
        return True

    def loop():
        interval = config.get("refresh_minutes", 30) * 60
        while not stop.is_set():
            try:
                do_refresh()
            except Exception as e:
                print("refresh failed:", e, file=sys.stderr)
            stop.wait(interval)

    with open(os.path.join(HERE, "web", "index.html"), "rb") as f:
        index = f.read()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # The page needs no third-party resources at all.
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'unsafe-inline'; "
                             "script-src 'unsafe-inline'; img-src data:")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", index)
            elif path == "/data.json":
                db = open_db(args.db)
                body = json.dumps(export(db)).encode()
                db.close()
                self._send(200, "application/json", body)
            else:
                self._send(404, "text/plain", b"not found")

        def do_POST(self):
            if urllib.parse.urlsplit(self.path).path != "/refresh":
                return self._send(404, "text/plain", b"not found")
            # Custom header = a cross-site page cannot trigger this without CORS.
            if self.headers.get("X-Secfeed") != "1":
                return self._send(403, "text/plain", b"forbidden")
            started = lock.locked() or threading.Thread(target=do_refresh, daemon=True).start()
            self._send(202, "application/json",
                       json.dumps({"already_running": bool(started)}).encode())

        def log_message(self, *a):
            pass

    threading.Thread(target=loop, daemon=True).start()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print("secfeed on http://%s:%d  (Ctrl-C to stop)" % (args.host, args.port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        stop.set()


def build(args, config):
    db = open_db(args.db)
    if not args.no_fetch:
        refresh(db, config)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(HERE, "web", "index.html"), "rb") as f:
        page = f.read()
    with open(os.path.join(args.out, "index.html"), "wb") as f:
        f.write(page)
    data = export(db)
    with open(os.path.join(args.out, "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f)
    print("wrote %d items to %s" % (len(data["items"]), args.out))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--config", default=os.path.join(HERE, "sources.json"))
    p.add_argument("--db", default=os.path.join(HERE, "secfeed.db"))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch", help="fetch all sources once")
    s = sub.add_parser("serve", help="serve the reader and refresh on a timer")
    s.add_argument("--host", default="127.0.0.1",
                   help="bind address (default: this machine only)")
    s.add_argument("--port", type=int, default=8787)
    b = sub.add_parser("build", help="write a static site")
    b.add_argument("out")
    b.add_argument("--no-fetch", action="store_true", help="use what is already in the db")
    args = p.parse_args(argv)
    config = load_config(args.config)
    if args.cmd == "fetch":
        db = open_db(args.db)
        print("stored %d items" % refresh(db, config))
    elif args.cmd == "serve":
        serve(args, config)
    elif args.cmd == "build":
        build(args, config)


if __name__ == "__main__":
    main()
