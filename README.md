# MAILSCOPE

**Email Header Analyzer** · Part of [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) · [H3AD-SEC Platform](https://h3ad-sec.github.io)

Paste raw email headers. Get SPF, DKIM, and DMARC verdicts, an ARC chain breakdown, visual hop chain, sender mismatch analysis, and risk flags for spoofing and impersonation — all client-side, nothing leaves your browser.

---

## What it does

| Section | Output |
|---|---|
| Verdict Banner | Single-line risk summary: HIGH / MEDIUM / LOW / CLEAN with auth overview |
| Auth Status | SPF / DKIM / DMARC badges (PASS / FAIL / SOFTFAIL / NONE) with selector, SPF domain, and DMARC policy |
| ARC Chain | Per-instance cv= status with SPF/DKIM/DMARC results (conditional — shown only when ARC headers are present) |
| Origin IP | Extracted from oldest Received header or X-Originating-IP, with one-click enrich to X-VERDIKT and PHISHOPS handoff |
| Risk Flags | Numbered list of anomalies with HIGH / MEDIUM / LOW severity |
| Hop Chain | Visual timeline oldest to newest, with IPs, per-hop delays, transit time, X-VERDIKT enrich for IPs, DNSCOPE pivot for hostnames |
| Sender Analysis | From vs. Reply-To vs. Return-Path vs. Message-ID vs. Delivered-To vs. X-Original-To domain comparison, envelope mismatch tags |
| Header Overview | Key headers in a clean table, with RFC 2047 encoded subjects decoded |
| Spam Filter | X-Spam-Status, X-Spam-Score, X-Spam-Flag (conditional, shown only if present) |
| Raw Headers | Collapsible view of all parsed single-value headers |
| Recent Analyses | Sidebar history (last 5 analyses) — verdict, hop count, flag count, sender, subject |
| Copy Analysis | Full plain-text export of the entire analysis to clipboard for ticket/case notes |

## Risk checks (16)

| Code | Level | Description |
|---|---|---|
| SPF_FAIL | HIGH | SPF authentication failed |
| SPF_SOFTFAIL | MEDIUM | SPF softfail (~all) |
| DKIM_FAIL | HIGH | DKIM signature invalid |
| DMARC_FAIL | HIGH | DMARC policy failed |
| RETURN_PATH_MISMATCH | HIGH | Return-Path domain differs from From |
| REPLY_REDIRECT | HIGH | Reply-To redirects to a different domain |
| MSGID_MISMATCH | MEDIUM | Message-ID domain differs from From |
| BRAND_IMPERSONATION | HIGH | Display name claims a known brand but domain doesn't match (22 brands) |
| HOMOGRAPH | HIGH | From domain uses digit/lookalike character substitution to impersonate a known brand |
| SUSPICIOUS_SUBJECT | MEDIUM | Subject contains a social-engineering phrase (urgent, verify, action required, etc.) |
| ENVELOPE_MISMATCH | MEDIUM | Delivered-To or X-Original-To differs from the To header |
| MISSING_DATE | LOW | No Date header present |
| FUTURE_DATE | MEDIUM | Date header is more than 5 minutes in the future |
| STALE_DATE | LOW | Date header is more than 30 days old |
| NO_HOPS | MEDIUM | No Received headers found (origin obscured) |
| SINGLE_HOP | LOW | Only one Received header (limited traceability) |
| FREE_RELAY | MEDIUM | Free mail provider in relay chain when From is a corporate domain |
| FAST_HOP | LOW | Hop transit under 1 second (suspicious for legitimate mail) |

## Parsing capabilities

- Header unfolding (RFC 2822 continuation lines)
- RFC 2047 subject decoding: base64 (`=?UTF-8?B?...?=`) and quoted-printable (`=?UTF-8?Q?...?=`)
- Multiple `Authentication-Results` headers merged (first definitive result per protocol wins)
- ARC-Seal and ARC-Authentication-Results: per-instance cv= plus SPF/DKIM/DMARC results
- `Received-SPF` fallback when `Authentication-Results` SPF is absent
- IPv4 and IPv6 hop IPs (`[IPv6:2001:db8::1]` format)
- DKIM selector extraction from `header.s=`
- SPF domain extraction from `smtp.mailfrom=`
- DMARC policy extraction from `action=` in auth-results
- Envelope fields: `Delivered-To`, `X-Original-To` vs `To` comparison
- Homograph detection: digit/lookalike character substitution across 22 known brands
- Suspicious subject pattern matching: 15 social-engineering phrase patterns
- Date header validation: missing, future-dated (+5 min), stale (30+ days)
- X-Spam headers: `X-Spam-Status`, `X-Spam-Score`, `X-Spam-Flag`
- `X-Originating-IP`, `X-Sender-IP`, `X-Source-IP` for origin IP
- Transit time calculated from oldest to newest hop timestamp
- Live header line count displayed in the input panel header

## Usage

1. Open your email client and copy the full raw headers:
   - Gmail: `...` menu > Show original > Copy to clipboard
   - Outlook: File > Properties > Internet headers
   - Thunderbird: More > View Page Source
2. Paste into MAILSCOPE and click **ANALYZE** (or `Ctrl+Enter`)
3. Check the verdict banner for a quick risk level
4. Review auth badges, ARC chain, risk flags, and hop chain
5. Click **X-VERDIKT ↗** on any hop IP to pivot to deep IP enrichment
6. Click **DNSCOPE ↗** on any hop hostname to pivot to domain infrastructure mapping
7. Click **PHISHOPS ↗** on the origin IP card to hand off to PHISHOPS with pre-filled context
8. Click **COPY ANALYSIS** to export the full breakdown as plain text for ticket notes

A sample phishing header is included — click **LOAD SAMPLE HEADER** to see all risk checks fire, including ARC chain, envelope mismatch, encoded subject decoding, and X-Spam flags.

## Architecture

Client-side only. No backend, no API calls, no data transmitted. All parsing runs in the browser via vanilla JavaScript.

```
MAILSCOPE/
├── index.html
├── css/style.css
└── js/
    ├── parser.js   — header unfolding, RFC 2047 decode, auth, ARC, hop chain, risk detection
    └── app.js      — UI rendering, verdict banner, history, export, event handling
```

## Part of H3AD-X

MAILSCOPE completes the IOC trifecta in H3AD-X:

| Tool | Covers |
|---|---|
| [X-VERDIKT](https://h3ad-sec.github.io/X-VERDIKT/) | IP addresses — deep enrichment across 11 sources |
| [DNSCOPE](https://h3ad-sec.github.io/DNSCOPE/) | Domains — infra mapping, ASN, certs, subdomains |
| [PARSE-X](https://h3ad-sec.github.io/PARSE-X/) | Raw text — extracts 18 artifact types |
| [MAILSCOPE](https://h3ad-sec.github.io/MAILSCOPE/) | Email headers — auth, ARC, hop chain, spoofing detection |

---

[H3AD-SEC](https://h3ad-sec.github.io) · Built for SOC analysts and detection engineers
