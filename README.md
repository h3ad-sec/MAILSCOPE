# MAILSCOPE

**Email Header Analyzer** · Part of [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) · [H3AD-SEC Platform](https://h3ad-sec.github.io)

Paste raw email headers. Get SPF, DKIM, and DMARC verdicts, a visual hop chain, sender mismatch analysis, and risk flags for spoofing and impersonation — all client-side, nothing leaves your browser.

---

## What it does

| Section | Output |
|---|---|
| Verdict Banner | Single-line risk summary: HIGH / MEDIUM / LOW / CLEAN with auth overview |
| Auth Status | SPF / DKIM / DMARC badges (PASS / FAIL / SOFTFAIL / NONE) with DKIM selector and SPF domain |
| Origin IP | Extracted from oldest Received header or X-Originating-IP, with one-click enrich to X-VERDIKT |
| Risk Flags | Numbered list of anomalies with HIGH / MEDIUM / LOW severity |
| Hop Chain | Visual timeline oldest to newest, with IPs, per-hop delays, transit time, and per-hop X-VERDIKT enrich links |
| Sender Analysis | From vs. Reply-To vs. Return-Path vs. Message-ID domain comparison with mismatch tags |
| Header Overview | Key headers in a clean table, with RFC 2047 encoded subjects decoded |
| Spam Filter | X-Spam-Status, X-Spam-Score, X-Spam-Flag (conditional, shown only if present) |
| Raw Headers | Collapsible view of all parsed single-value headers |
| Copy Analysis | Full plain-text export of the entire analysis to clipboard for ticket/case notes |

## Risk checks (10)

- SPF fail / softfail
- DKIM signature invalid
- DMARC policy failed
- Return-Path domain mismatch
- Reply-To redirects to a different domain (harvest indicator)
- Message-ID domain differs from From
- Brand impersonation: display name claims a known brand but domain doesn't match (22 brands)
- No Received headers (origin obscured)
- Single hop only (limited traceability)
- Free mail provider in relay chain when From is a corporate domain

## Parsing capabilities

- Header unfolding (RFC 2822 continuation lines)
- RFC 2047 subject decoding: base64 (`=?UTF-8?B?...?=`) and quoted-printable (`=?UTF-8?Q?...?=`)
- Multiple `Authentication-Results` headers merged (ARC chains supported)
- `Received-SPF` fallback when `Authentication-Results` SPF is absent
- IPv4 and IPv6 hop IPs (`[IPv6:2001:db8::1]` format)
- DKIM selector extraction from auth-results
- SPF domain extraction from `smtp.mailfrom`
- X-Spam headers: `X-Spam-Status`, `X-Spam-Score`, `X-Spam-Flag`
- `X-Originating-IP`, `X-Sender-IP`, `X-Source-IP` for origin IP
- Transit time calculated from oldest to newest hop timestamp

## Usage

1. Open your email client and copy the full raw headers:
   - Gmail: `...` menu > Show original > Copy to clipboard
   - Outlook: File > Properties > Internet headers
   - Thunderbird: More > View Page Source
2. Paste into MAILSCOPE and click **ANALYZE** (or `Ctrl+Enter`)
3. Check the verdict banner for a quick risk level
4. Review auth badges, risk flags, and hop chain
5. Click **X-VERDIKT ↗** on any hop IP to pivot to deep IP enrichment
6. Click **COPY ANALYSIS** to export the full breakdown as plain text for ticket notes

A sample phishing header is included — click **LOAD SAMPLE HEADER** to see all risk checks fire, including encoded subject decoding and X-Spam flags.

## Architecture

Client-side only. No backend, no API calls, no data transmitted. All parsing runs in the browser via vanilla JavaScript.

```
MAILSCOPE/
├── index.html
├── css/style.css
└── js/
    ├── parser.js   — header unfolding, RFC 2047 decode, auth parsing, hop chain, risk detection
    └── app.js      — UI rendering, verdict banner, export, event handling
```

## Part of H3AD-X

MAILSCOPE completes the IOC trifecta in H3AD-X:

| Tool | Covers |
|---|---|
| [X-VERDIKT](https://h3ad-sec.github.io/X-VERDIKT/) | IP addresses — deep enrichment across 10 sources |
| [DNSCOPE](https://h3ad-sec.github.io/DNSCOPE/) | Domains — infra mapping, ASN, certs, subdomains |
| [PARSE-X](https://h3ad-sec.github.io/PARSE-X/) | Raw text — extracts 18 artifact types |
| [MAILSCOPE](https://h3ad-sec.github.io/MAILSCOPE/) | Email headers — auth, hop chain, spoofing detection |

---

[H3AD-SEC](https://h3ad-sec.github.io) · Built for SOC analysts and detection engineers
