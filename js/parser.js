// MAILSCOPE — parser.js

const MailParser = (() => {

  // ── RFC 2047 decode ────────────────────────────────────────────────────────

  function decodeRFC2047(str) {
    if (!str || !str.includes('=?')) return str || '';
    return str.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, enc, text) => {
      try {
        if (enc.toUpperCase() === 'B') {
          const bytes = Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
          return new TextDecoder(charset).decode(bytes);
        }
        return text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (__, h) => String.fromCharCode(parseInt(h, 16)));
      } catch (_) { return text; }
    }).replace(/\?=\s+=\?[^?]+\?[BbQq]\?/g, ''); // collapse adjacent encoded words
  }

  // ── Header parsing ─────────────────────────────────────────────────────────

  function unfold(raw) {
    return raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n([ \t]+)/g, ' ');
  }

  function parseHeaders(raw) {
    const lines  = unfold(raw).split('\n');
    const single = {};
    const multi  = { received: [], authResults: [], arcSeals: [], arcAuthResults: [] };

    for (const line of lines) {
      const m = line.match(/^([A-Za-z0-9\-]+)\s*:\s*(.*)/);
      if (!m) continue;
      const key = m[1].toLowerCase();
      const val = m[2].trim();

      switch (key) {
        case 'received':                  multi.received.push(val); break;
        case 'authentication-results':    multi.authResults.push(val); break;
        case 'arc-authentication-results': multi.arcAuthResults.push(val); break;
        case 'arc-seal':                  multi.arcSeals.push(val); break;
        default:
          if (!(key in single)) single[key] = val;
      }
    }
    return { single, multi };
  }

  // ── Address helpers ────────────────────────────────────────────────────────

  function parseAddr(str) {
    if (!str) return { display: '', addr: '', domain: '' };
    const angled = str.match(/<([^>]+)>/);
    const addr   = angled ? angled[1].trim() : str.replace(/^['"\s]+|['"\s]+$/g, '');
    const domM   = addr.match(/@([^@\s>]+)$/);
    const domain = domM ? domM[1].toLowerCase() : '';
    const display = str.replace(/<[^>]+>/, '').replace(/['"]/g, '').trim();
    return { display, addr, domain };
  }

  // ── Auth parsing ───────────────────────────────────────────────────────────

  function parseAuthResults(authArr) {
    const auth = {
      spf: 'none', dkim: 'none', dmarc: 'none',
      dkimSelector: '', spfDomain: '', dmarcPolicy: '', dmarcDomain: ''
    };
    for (const val of authArr) {
      const spf   = val.match(/\bspf=([a-z]+)/i);
      const dkim  = val.match(/\bdkim=([a-z]+)/i);
      const dmarc = val.match(/\bdmarc=([a-z]+)/i);
      const sel   = val.match(/header\.s=([^\s;,]+)/i);
      const spfD  = val.match(/smtp\.mailfrom=([^\s;,]+)/i) || val.match(/smtp\.helo=([^\s;,]+)/i);
      const pol   = val.match(/\baction=(none|quarantine|reject)/i);
      const dDom  = val.match(/header\.from=([^\s;,]+)/i);

      if (spf   && auth.spf   === 'none') auth.spf   = spf[1].toLowerCase();
      if (dkim  && auth.dkim  === 'none') auth.dkim  = dkim[1].toLowerCase();
      if (dmarc && auth.dmarc === 'none') auth.dmarc = dmarc[1].toLowerCase();
      if (sel   && !auth.dkimSelector)    auth.dkimSelector = sel[1];
      if (spfD  && !auth.spfDomain)       auth.spfDomain    = spfD[1];
      if (pol   && !auth.dmarcPolicy)     auth.dmarcPolicy  = pol[1].toLowerCase();
      if (dDom  && !auth.dmarcDomain)     auth.dmarcDomain  = dDom[1].toLowerCase();
    }
    return auth;
  }

  function parseReceivedSPF(val) {
    if (!val) return null;
    const result = val.match(/^([a-z]+)/i);
    return { result: result ? result[1].toLowerCase() : 'unknown', detail: val.trim() };
  }

  // ── ARC chain ──────────────────────────────────────────────────────────────

  function parseARC(arcSeals, arcAuthResults) {
    if (!arcSeals.length && !arcAuthResults.length) return null;

    const seals = arcSeals.map(s => {
      const iM  = s.match(/\bi=(\d+)/i);
      const cvM = s.match(/\bcv=([a-z]+)/i);
      return { instance: iM ? parseInt(iM[1]) : 0, cv: cvM ? cvM[1].toLowerCase() : 'unknown' };
    }).sort((a, b) => a.instance - b.instance);

    const authInstances = arcAuthResults.map(s => {
      const iM   = s.match(/\bi=(\d+)/i);
      const spf  = s.match(/\bspf=([a-z]+)/i);
      const dkim = s.match(/\bdkim=([a-z]+)/i);
      const dmarc = s.match(/\bdmarc=([a-z]+)/i);
      return {
        instance: iM ? parseInt(iM[1]) : 0,
        spf:   spf  ? spf[1].toLowerCase()  : 'none',
        dkim:  dkim ? dkim[1].toLowerCase() : 'none',
        dmarc: dmarc ? dmarc[1].toLowerCase() : 'none'
      };
    }).sort((a, b) => a.instance - b.instance);

    // Merge by instance
    const instances = {};
    for (const s of seals)          instances[s.instance] = { ...s };
    for (const a of authInstances)  instances[a.instance] = { ...(instances[a.instance] || {}), ...a };

    const finalCV = seals.length ? seals[seals.length - 1].cv : 'unknown';
    return { instances: Object.values(instances).sort((a, b) => a.instance - b.instance), finalCV };
  }

  // ── Hop parsing ────────────────────────────────────────────────────────────

  function parseReceivedHop(raw) {
    const ipv4M = raw.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
    const ipv6M = raw.match(/\[IPv6:([^\]]+)\]/i) || raw.match(/\[([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})\]/);
    const ip    = ipv4M ? ipv4M[1] : (ipv6M ? ipv6M[1] : null);

    const fromM = raw.match(/\bfrom\s+([^\s\[;(]+)/i);
    const byM   = raw.match(/\bby\s+([^\s\[;(]+)/i);
    const withM = raw.match(/\bwith\s+([^\s;(]+)/i);
    const tsM   = raw.match(/;\s*(.+)$/);
    const tsRaw = tsM ? tsM[1].trim() : '';

    let ts = null;
    if (tsRaw) {
      try { const d = new Date(tsRaw); if (!isNaN(d.getTime())) ts = d; } catch (_) {}
    }
    return {
      ip, from: fromM ? fromM[1] : '', by: byM ? byM[1] : '',
      proto: withM ? withM[1] : '', ts, tsRaw
    };
  }

  // ── X-Spam ────────────────────────────────────────────────────────────────

  function parseXSpam(single) {
    const status = single['x-spam-status'] || null;
    const score  = single['x-spam-score']  || null;
    const flag   = single['x-spam-flag']   || null;
    if (!status && !score && !flag) return null;
    return { status, score, flag };
  }

  // ── Transit time ──────────────────────────────────────────────────────────

  function calcTransit(hops) {
    const ordered = [...hops].reverse();
    const first   = ordered.find(h => h.ts);
    const last    = [...ordered].reverse().find(h => h.ts);
    if (!first || !last || first === last) return null;
    return Math.round(Math.abs(last.ts - first.ts) / 1000);
  }

  // ── Risk detection ────────────────────────────────────────────────────────

  const FREE_PROVIDERS = [
    'gmail.com','yahoo.com','hotmail.com','outlook.com','live.com',
    'aol.com','protonmail.com','yandex.com','mail.com','icloud.com','zoho.com'
  ];

  const BRANDS = [
    'paypal','microsoft','google','apple','amazon','netflix','facebook',
    'instagram','twitter','linkedin','dropbox','docusign','chase',
    'wellsfargo','citibank','bankofamerica','hsbc','barclays','adobe',
    'salesforce','intuit','quickbooks'
  ];

  const SUSPICIOUS_SUBJECT = [
    /\[urgent\]/i, /\[action\s+required\]/i, /\[important\]/i, /\[security\s+alert\]/i,
    /verify\s+your\s+(account|identity|email|payment|information)/i,
    /account\s+(limited|suspended|restricted|locked|compromised|deactivated)/i,
    /unusual\s+(sign-in|login|activity|access)/i,
    /confirm\s+(your|account|payment|identity|details)/i,
    /password\s+(expired|reset|changed|update)/i,
    /(invoice|payment)\s+(attached|due|overdue|pending|required)/i,
    /security\s+(alert|notice|warning|update)/i,
    /your\s+(account|payment|order)\s+(has been|was|will be)\s+(limited|suspended|charged|closed)/i,
    /click\s+here\s+to\s+(verify|confirm|update|restore)/i,
    /immediately\s+(verify|confirm|update)/i,
  ];

  // Digit/character substitution homograph check
  function detectHomograph(domain) {
    if (!domain) return null;
    const parts = domain.split('.');
    const sld   = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
    const normalized = sld
      .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
      .replace(/4/g, 'a').replace(/5/g, 's').replace(/6/g, 'g')
      .replace(/7/g, 't').replace(/8/g, 'b').replace(/\|/g, 'l')
      .replace(/vv/g, 'w').replace(/rn/g, 'm').replace(/nn/g, 'm');
    for (const brand of BRANDS) {
      if (normalized.includes(brand) && !sld.includes(brand)) return brand;
    }
    return null;
  }

  function detectRisks(data) {
    const {
      auth, fromInfo, replyToInfo, returnPathInfo, msgIdDomain, hops,
      subject, dateStr, deliveredTo, xOriginalTo, toInfo
    } = data;
    const flags = [];

    // ── Auth failures ──────────────────────────────────────────────────────
    if (auth.spf === 'fail') {
      flags.push({ code: 'SPF_FAIL', level: 'high', title: 'SPF authentication failed', detail: 'The sending server is not authorized to send on behalf of the From domain. Strong spoofing indicator.' });
    } else if (auth.spf === 'softfail') {
      flags.push({ code: 'SPF_SOFTFAIL', level: 'medium', title: 'SPF soft fail', detail: 'Sender not explicitly authorized. Possible spoofing or domain misconfiguration.' });
    }
    if (auth.dkim === 'fail') {
      flags.push({ code: 'DKIM_FAIL', level: 'high', title: 'DKIM signature invalid', detail: 'Email content may have been modified in transit, or the signature does not match the sending domain.' });
    }
    if (auth.dmarc === 'fail') {
      const enforcement = auth.dmarcPolicy ? ` Policy enforcement: ${auth.dmarcPolicy}.` : '';
      flags.push({ code: 'DMARC_FAIL', level: 'high', title: 'DMARC policy failed', detail: `Email failed the sending domain's authentication policy.${enforcement} High-confidence spoofing indicator.` });
    }

    // ── Domain mismatches ──────────────────────────────────────────────────
    if (fromInfo.domain && returnPathInfo.domain && fromInfo.domain !== returnPathInfo.domain) {
      flags.push({ code: 'RETURN_PATH_MISMATCH', level: 'medium', title: 'Return-Path domain mismatch', detail: `From: ${fromInfo.domain} vs Return-Path: ${returnPathInfo.domain}. Bounces route to a different domain than the claimed sender.` });
    }
    if (replyToInfo.domain && fromInfo.domain && replyToInfo.domain !== fromInfo.domain) {
      flags.push({ code: 'REPLY_REDIRECT', level: 'medium', title: 'Reply-To redirects to a different domain', detail: `Replies go to ${replyToInfo.domain}, not ${fromInfo.domain}. Common in credential-harvest phishing campaigns.` });
    }
    if (msgIdDomain && fromInfo.domain && msgIdDomain !== fromInfo.domain) {
      flags.push({ code: 'MSGID_MISMATCH', level: 'low', title: 'Message-ID domain differs from From', detail: `Message-ID uses ${msgIdDomain} but From claims ${fromInfo.domain}. Email may have been generated by a third-party system.` });
    }

    // ── Envelope mismatch ──────────────────────────────────────────────────
    const envelopeTo = deliveredTo || xOriginalTo;
    if (envelopeTo && toInfo.addr) {
      const envAddr   = envelopeTo.replace(/[<>]/g, '').trim().toLowerCase();
      const hdrAddr   = toInfo.addr.toLowerCase();
      if (envAddr && hdrAddr && envAddr !== hdrAddr) {
        flags.push({ code: 'ENVELOPE_MISMATCH', level: 'medium', title: 'Envelope-to differs from header To', detail: `Delivered-To/X-Original-To: ${envelopeTo} vs To: ${toInfo.addr}. May indicate BCC targeting, list-based delivery, or header manipulation.` });
      }
    }

    // ── Impersonation ──────────────────────────────────────────────────────
    const displayLower = (fromInfo.display || '').toLowerCase();
    for (const brand of BRANDS) {
      if (displayLower.includes(brand) && fromInfo.domain && !fromInfo.domain.includes(brand)) {
        flags.push({ code: 'BRAND_IMPERSONATION', level: 'high', title: `Brand impersonation: ${brand}`, detail: `Display name claims "${fromInfo.display}" but the actual sending domain is "${fromInfo.domain}".` });
        break;
      }
    }

    // ── Homograph domain ───────────────────────────────────────────────────
    const homoBrand = detectHomograph(fromInfo.domain);
    if (homoBrand) {
      flags.push({ code: 'HOMOGRAPH', level: 'high', title: `Homograph domain impersonating: ${homoBrand}`, detail: `Domain "${fromInfo.domain}" uses character substitution to resemble "${homoBrand}". Digit/lookalike substitution detected.` });
    }

    // ── Suspicious subject ─────────────────────────────────────────────────
    if (subject) {
      for (const pattern of SUSPICIOUS_SUBJECT) {
        if (pattern.test(subject)) {
          flags.push({ code: 'SUSPICIOUS_SUBJECT', level: 'medium', title: 'Suspicious subject line pattern', detail: `Subject contains a social-engineering phrase: "${subject.slice(0, 100)}${subject.length > 100 ? '...' : ''}"` });
          break;
        }
      }
    }

    // ── Date validation ────────────────────────────────────────────────────
    if (!dateStr) {
      flags.push({ code: 'MISSING_DATE', level: 'medium', title: 'Date header absent', detail: 'Every legitimate MTA stamps a Date header. Its absence indicates manual header construction or stripping.' });
    } else {
      try {
        const emailDate = new Date(dateStr);
        if (!isNaN(emailDate.getTime())) {
          const now  = Date.now();
          const diff = emailDate.getTime() - now;
          if (diff > 86400000) {
            flags.push({ code: 'FUTURE_DATE', level: 'medium', title: 'Email is future-dated', detail: `Date header is ${Math.round(diff / 3600000)}h in the future. May indicate header manipulation or timezone abuse.` });
          } else if (now - emailDate.getTime() > 30 * 86400000) {
            flags.push({ code: 'STALE_DATE', level: 'low', title: 'Email is more than 30 days old', detail: `Date header indicates this email was sent ${Math.round((now - emailDate.getTime()) / 86400000)} days ago. Verify this is expected.` });
          }
        }
      } catch (_) {}
    }

    // ── Hop analysis ───────────────────────────────────────────────────────
    if (hops.length === 0) {
      flags.push({ code: 'NO_HOPS', level: 'medium', title: 'No Received headers found', detail: 'Hop chain is absent. Headers may have been stripped or the email was manually composed.' });
    } else if (hops.length === 1) {
      flags.push({ code: 'SINGLE_HOP', level: 'low', title: 'Single hop only', detail: 'Limited traceability. Origin may be partially obscured.' });
    }

    const isCorpFrom = fromInfo.domain && !FREE_PROVIDERS.some(fp => fromInfo.domain.includes(fp));
    if (isCorpFrom) {
      for (const hop of hops) {
        if (hop.from && FREE_PROVIDERS.some(fp => hop.from.toLowerCase().includes(fp))) {
          flags.push({ code: 'FREE_RELAY', level: 'medium', title: 'Free mail provider in relay chain', detail: `${hop.from} appeared as a relay hop despite the sender claiming a corporate domain (${fromInfo.domain}).` });
          break;
        }
      }
    }

    const ordered = [...hops].reverse();
    for (let i = 1; i < ordered.length; i++) {
      if (ordered[i - 1].ts && ordered[i].ts) {
        const diff = Math.abs(ordered[i].ts - ordered[i - 1].ts) / 1000;
        if (diff < 1) {
          flags.push({ code: 'FAST_HOP', level: 'low', title: 'Sub-second hop delay', detail: `Hop ${i}: ${diff.toFixed(2)}s between relays. May indicate automated bulk sending.` });
          break;
        }
      }
    }

    return flags;
  }

  // ── Main analyze ──────────────────────────────────────────────────────────

  function analyze(raw) {
    const { single, multi } = parseHeaders(raw);

    const fromInfo       = parseAddr(single['from']        || '');
    const replyToInfo    = parseAddr(single['reply-to']    || '');
    const returnPathInfo = parseAddr(single['return-path'] || '');
    const toInfo         = parseAddr(single['to']          || '');

    const msgId       = single['message-id'] || '';
    const msgIdDomM   = msgId.match(/@([^@>\s]+)/);
    const msgIdDomain = msgIdDomM ? msgIdDomM[1].replace(/>/g, '').toLowerCase() : '';

    const auth = parseAuthResults(multi.authResults);
    const receivedSPF = parseReceivedSPF(single['received-spf'] || '');
    if (auth.spf === 'none' && receivedSPF) auth.spf = receivedSPF.result;

    const arc  = parseARC(multi.arcSeals, multi.arcAuthResults);
    const hops = multi.received.map(parseReceivedHop);

    const xIp = (single['x-originating-ip'] || single['x-sender-ip'] || single['x-source-ip'] || '').replace(/[[\]\s]/g, '');
    const firstHopIp = xIp || (hops.length > 0 ? hops[hops.length - 1].ip : null) || null;

    const decodedSubject = decodeRFC2047(single['subject'] || '');
    const transitSeconds = calcTransit(hops);
    const xSpam          = parseXSpam(single);

    const deliveredTo  = single['delivered-to']    || '';
    const xOriginalTo  = single['x-original-to']   || '';

    const risks = detectRisks({
      auth, fromInfo, replyToInfo, returnPathInfo, msgIdDomain, hops,
      subject: decodedSubject, dateStr: single['date'] || '',
      deliveredTo, xOriginalTo, toInfo
    });

    // Total header count for the chip
    const headerCount = Object.keys(single).length + multi.received.length +
      multi.authResults.length + multi.arcSeals.length + multi.arcAuthResults.length;

    return {
      overview: {
        from:        single['from']         || '',
        to:          single['to']           || '',
        subject:     decodedSubject,
        date:        single['date']         || '',
        messageId:   msgId,
        replyTo:     single['reply-to']     || '',
        returnPath:  single['return-path']  || '',
        xMailer:     single['x-mailer'] || single['user-agent'] || '',
        contentType: single['content-type'] || '',
        deliveredTo, xOriginalTo
      },
      fromInfo, replyToInfo, returnPathInfo, toInfo,
      msgIdDomain, auth, receivedSPF, arc, hops,
      firstHopIp, transitSeconds, xSpam, risks,
      headerCount, allHeaders: single
    };
  }

  return { analyze };
})();
