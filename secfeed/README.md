# secfeed

A personal security news reader. It pulls CVEs, known-exploited alerts,
security news and AI-security research (prompt injection, jailbreaks, agent
attacks) into one local feed.

It is self-contained in this directory and unrelated to qtop. It uses only the
Python standard library (3.9+), so there is nothing to install.

![screenshot](screenshot.png)

## Run it

```sh
cd secfeed
python3 secfeed.py serve          # then open http://127.0.0.1:8787
```

`serve` fetches every source at start, again every 30 minutes, and serves the
reader. It binds to `127.0.0.1`, so only this machine can reach it. To read it
from your phone on the same network, pass `--host 0.0.0.0` (anyone on that
network can then open it; there is no login).

Other commands:

```sh
python3 secfeed.py fetch          # fetch once and exit (for cron)
python3 secfeed.py build site/    # write index.html + data.json for static hosting
python3 -m unittest discover -s tests
```

## What it reads

| Tab | What it shows | Sources |
| --- | --- | --- |
| Priority | Recent CVEs ranked by how likely they are to hurt | computed, see below |
| CVEs | New vulnerabilities | NVD (CVSS 7.0+), CISA KEV, GitHub Advisories, ZDI advisories, oss-security |
| Exploited | Anything seen or reported in real attacks | CISA KEV plus keyword matches in every feed |
| Exploits | Public exploit code and disclosures | Exploit-DB, Full Disclosure, new GitHub repos named after a CVE |
| News | Security news and breaches | The Hacker News, BleepingComputer, Krebs, SANS ISC, Schneier, SecurityWeek, The Record, Dark Reading, Tom's Hardware, The Register, Have I Been Pwned |
| Research | Technique and threat write-ups | PortSwigger Research, watchTowr Labs, ZDI blog, Unit 42, Cisco Talos, The DFIR Report, Trail of Bits, Rapid7 |
| AI security | Prompt injection, jailbreaks, agent attacks | Simon Willison, Embrace The Red, arXiv, Hacker News, GitHub, plus AI stories from every other feed |
| Tools | New releases of testing tools | GitHub releases of nuclei, nuclei-templates, Metasploit, sqlmap, ffuf, Impacket, BloodHound, ZAP, Ghidra, hashcat |
| Practice | Legal hands-on practice | CTFtime upcoming CTFs, InfoSec Write-ups |
| Social | Posts | X and Threads, with API tokens (see below) |
| Saved | Items you starred | kept in your browser, outlives the 30-day history |

### CVE categories

On the Priority, CVEs, Exploited and Exploits tabs, two rows of filter chips
sort vulnerabilities by **what they affect** (Windows, Microsoft, Android
phones, iPhone & Apple, WordPress & CMS, Network & VPN, Linux & Unix,
Browsers, Cloud & virtualization, IoT & industrial, Databases, Enterprise
apps, Dev tools & libraries, Web apps & APIs, AI & ML) and by **kind of
attack** (remote code execution, memory
corruption, SQL injection, cross-site scripting, auth & access bypass,
privilege escalation, file access, request forgery, information leak, denial
of service). Tap one from each row to combine them, for example "Network &
VPN" plus "Remote code execution".

Categories come from the published weakness type (CWE) where there is one and
from keywords in the description otherwise, so some items land in "Other" and
a few will be misfiled. The rules are the `AREAS` and `ATTACKS` lists at the
top of `secfeed.py` and are easy to extend.

### AI model / tool

On the **AI security** tab a chip row sorts items by which model or tool they
concern: ChatGPT / OpenAI, Claude / Anthropic, Gemini / Google, Copilot /
Microsoft, Llama / Meta, Grok / xAI, Mistral, DeepSeek, coding agents (Cursor,
Copilot, Aider…), agents & MCP, RAG & embeddings, and local or open models.
An item can match several, and anything that names no specific model lands in
"General". The rules are the `AI_MODELS` list in `secfeed.py`.

### Priority ranking

Most high-severity CVEs are never attacked, so severity alone is a poor guide.
The Priority tab ranks CVEs from the last 14 days by evidence of real risk, and
each item's detail view says why it ranks:

- it is on CISA's Known Exploited Vulnerabilities list, or reported as exploited;
- exploit code for it is public somewhere in the feed (items get an "EXPLOIT PUBLIC" badge);
- its EPSS score, the published estimate of the chance it is exploited in the next 30 days;
- its CVSS severity;
- it matches your watchlist.

### Push alerts

The server can notify your phone when something new and urgent arrives. The
simplest route is [ntfy](https://ntfy.sh): install the app, subscribe to a
topic name only you know, and start the server with

```sh
SECFEED_ALERT_URL=https://ntfy.sh/your-secret-topic python3 secfeed.py serve
```

Discord and Slack webhook URLs work too. By default it alerts on new CISA KEV
entries; add vendors or products you run to `alerts.keywords` in
`sources.json` to be told about anything mentioning them. Alerts are sent only
for items the server has not seen before, never on its first run, and are
capped per refresh. Anyone who knows an ntfy topic name can read it, so pick
an unguessable one.

Tap any item to open its detail view: the link, a plain-language explanation
(how it can be attacked, what an attacker gains, what to do), the full
description, affected products, references and related items in your feed.
The explanation is built from facts the sources publish (the CVSS vector,
weakness type and CISA status), so it needs no AI service or API key.

![detail view](screenshot-detail.png)

The reader also cross-links: any item that mentions a CVE gets a clickable
chip, a news story about a CVE that is in CISA KEV is flagged "known
exploited", and anything about AI tooling from any source also appears under
"AI security". The Watchlist button stores keywords (vendors, products) in
your browser and gives matches their own tab.

## Optional tokens

Set these as environment variables before running. None are stored on disk.

| Variable | Effect |
| --- | --- |
| `GITHUB_TOKEN` | Raises GitHub's rate limit (unauthenticated search allows 10 requests a minute, which is enough for the defaults). |
| `NVD_API_KEY` | Raises NVD's rate limit. Free from nvd.nist.gov. |
| `X_BEARER_TOKEN` | Enables the X source. X's API is paid; without the token the source is skipped. |
| `SECFEED_ALERT_URL` | Turns on push alerts (ntfy topic URL, or a Discord or Slack webhook). |
| `THREADS_ACCESS_TOKEN` | Enables the Threads sources. Needs a Meta developer app with the `threads_keyword_search` permission. |

There is no free, sanctioned way to read X or Threads, and scraping them
breaks their terms and breaks often, so those two sources stay off until you
supply a token. The X and Threads fetchers are tested against the documented
response shapes only; they have not been run against the live APIs.

## Changing sources

Edit `sources.json`. Each entry has a `type` (`rss`, `nvd`, `kev`, `ghsa`,
`github_search`, `github_releases`, `hn`, `x`, `threads`), a `name`, and a
`category` (`cve`, `exploit`, `news`, `research`, `ai`, `tools`, `learn`,
`social`). Adding a blog is one line:

```json
{"type": "rss", "name": "Some Blog", "category": "news", "url": "https://example.com/feed.xml"}
```

Set `"enabled": false` to switch a source off. For NVD, `min_severity` sets
the CVSS floor (NVD publishes several hundred CVEs a day; CVEs about AI tooling
are kept whatever their score). The Sources panel at the bottom of the reader
shows each source's last result, including why one failed.

## Use it responsibly

The feed lists public exploit code and attack techniques so you can patch,
detect and test. Only test systems you own or have written permission to
test. Treat proof-of-concept repositories from unknown authors as hostile:
read the code and run it only in an isolated lab, because fake PoCs that
carry malware are common.

## Safety notes

Feeds are untrusted input. Summaries are reduced to plain text on the way in,
only `http(s)` links are kept, the page inserts everything as text rather than
HTML, and the server sends a Content-Security-Policy that allows no
third-party resources.
