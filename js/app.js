// MAILSCOPE — app.js

const SAMPLE = `Received: from mail.suspicious-relay.xyz (mail.suspicious-relay.xyz [185.220.101.45])
        by mx.corp-mail.com with ESMTPS id a1b2c3d4e5
        for <employee@corp-mail.com>; Thu, 28 May 2026 09:15:03 +0000
Received: from localhost (localhost [127.0.0.1])
        by mail.suspicious-relay.xyz with ESMTP id z9y8x7w6v5
        for <employee@corp-mail.com>; Thu, 28 May 2026 09:15:01 +0000
Authentication-Results: mx.corp-mail.com;
        spf=fail (sender IP is 185.220.101.45) smtp.mailfrom=support@paypal-secure.net;
        dkim=fail header.d=paypal-secure.net header.s=selector1;
        dmarc=fail action=none header.from=paypal.com
From: "PayPal Security Team" <security@paypal-secure.net>
Reply-To: harvest2026@gmail.com
To: employee@corp-mail.com
Subject: =?UTF-8?B?W1VSR0VOVF0gWW91ciBQYXlQYWwgYWNjb3VudCBoYXMgYmVlbiBsaW1pdGVk?=
Date: Thu, 28 May 2026 09:14:58 +0000
Message-ID: <20260528091458.ABCDE@suspicious-relay.xyz>
Return-Path: <bounces@paypal-secure.net>
X-Mailer: PHPMailer 6.5.3
X-Spam-Status: Yes, score=8.4
X-Spam-Score: 8.4
X-Spam-Flag: YES
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8`;

let _lastResult = null;

// ─── Init ──────────────────────────────────────────────────────────────────────

document.getElementById('ms-input').addEventListener('input', function () {
  document.getElementById('analyze-btn').disabled = !this.value.trim();
});

document.addEventListener('keydown', function (e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    const btn = document.getElementById('analyze-btn');
    if (!btn.disabled) runAnalysis();
  }
});

function loadSample() {
  document.getElementById('ms-input').value = SAMPLE;
  document.getElementById('analyze-btn').disabled = false;
}

function clearAll() {
  document.getElementById('ms-input').value = '';
  document.getElementById('analyze-btn').disabled = true;
  document.getElementById('results-section').style.display = 'none';
  document.getElementById('copy-analysis-row').style.display = 'none';
  document.getElementById('empty-state').style.display = '';
  _lastResult = null;
}

// ─── Analysis ─────────────────────────────────────────────────────────────────

function runAnalysis() {
  const raw = document.getElementById('ms-input').value.trim();
  if (!raw) return;
  try {
    const r = MailParser.analyze(raw);
    _lastResult = r;
    renderAll(r);
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('results-section').style.display = 'flex';
    document.getElementById('copy-analysis-row').style.display = '';
  } catch (err) {
    console.error('MAILSCOPE error:', err);
  }
}

// ─── Render ────────────────────────────────────────────────────────────────────

function renderAll(r) {
  renderVerdict(r.risks, r.auth);
  renderAuth(r.auth);
  renderHopChain(r.hops, r.transitSeconds);
  renderOverview(r.overview);
  renderSenderAnalysis(r);
  renderRiskFlags(r.risks);
  renderFirstHop(r.firstHopIp);
  renderXSpam(r.xSpam);
  renderRaw(r.allHeaders);

  const high = r.risks.filter(f => f.level === 'high').length;
  document.getElementById('stat-hops').textContent = r.hops.length || '0';
  document.getElementById('stat-flags').textContent = r.risks.length || '0';
  document.getElementById('stat-high').textContent = high || '0';
  document.getElementById('stat-transit').textContent = formatTransit(r.transitSeconds);
}

function formatTransit(s) {
  if (s === null) return 'N/A';
  if (s < 60) return s + 's';
  if (s < 3600) return Math.round(s / 60) + 'm';
  return Math.round(s / 3600) + 'h';
}

// ─── Verdict banner ────────────────────────────────────────────────────────────

function renderVerdict(risks, auth) {
  const el = document.getElementById('verdict-banner');
  const high   = risks.filter(f => f.level === 'high').length;
  const medium = risks.filter(f => f.level === 'medium').length;
  const low    = risks.filter(f => f.level === 'low').length;

  let level, label;
  if (high > 0)             { level = 'high';   label = 'HIGH RISK'; }
  else if (medium > 0)      { level = 'medium'; label = 'MEDIUM RISK'; }
  else if (low > 0)         { level = 'low';    label = 'LOW RISK'; }
  else                      { level = 'clean';  label = 'CLEAN'; }

  const authSummary = ['SPF', 'DKIM', 'DMARC']
    .map(p => `${p}: ${(auth[p.toLowerCase()] || 'NONE').toUpperCase()}`)
    .join(' · ');

  const countParts = [];
  if (high)   countParts.push(`<span class="vc-high">${high} HIGH</span>`);
  if (medium) countParts.push(`<span class="vc-medium">${medium} MED</span>`);
  if (low)    countParts.push(`<span class="vc-low">${low} LOW</span>`);

  el.className = `verdict-banner verdict-${level}`;
  el.innerHTML = `
    <div class="verdict-left">
      <span class="verdict-label">${label}</span>
      <span class="verdict-auth">${authSummary}</span>
    </div>
    <div class="verdict-counts">
      ${countParts.join('') || '<span class="vc-low">NO FLAGS</span>'}
    </div>`;
}

// ─── Auth ──────────────────────────────────────────────────────────────────────

function authClass(val) {
  if (val === 'pass')     return 'auth-pass';
  if (val === 'fail')     return 'auth-fail';
  if (val === 'softfail') return 'auth-warn';
  return 'auth-none';
}

function renderAuth(auth) {
  const protos = [
    { key: 'spf',   label: 'SPF' },
    { key: 'dkim',  label: 'DKIM' },
    { key: 'dmarc', label: 'DMARC' }
  ];
  document.getElementById('auth-badges').innerHTML = protos.map(({ key, label }) => {
    const val = auth[key] || 'none';
    const extra = (key === 'dkim' && auth.dkimSelector)
      ? `<span class="auth-sub">selector: ${esc(auth.dkimSelector)}</span>`
      : (key === 'spf' && auth.spfDomain)
      ? `<span class="auth-sub">${esc(auth.spfDomain)}</span>`
      : '';
    return `
      <div class="auth-badge ${authClass(val)}">
        <span class="auth-proto">${label}</span>
        <span class="auth-val">${val.toUpperCase()}</span>
        ${extra}
      </div>`;
  }).join('');
}

// ─── Hop chain ─────────────────────────────────────────────────────────────────

function renderHopChain(hops, transitSeconds) {
  const el       = document.getElementById('hop-chain');
  const titleEl  = document.getElementById('hop-chain-meta');

  if (transitSeconds !== null && titleEl) {
    titleEl.textContent = `${hops.length} hop${hops.length !== 1 ? 's' : ''} · ${formatTransit(transitSeconds)} transit`;
  } else if (titleEl) {
    titleEl.textContent = `${hops.length} hop${hops.length !== 1 ? 's' : ''}`;
  }

  if (!hops.length) {
    el.innerHTML = '<p class="no-data">No Received headers found.</p>';
    return;
  }

  const ordered = [...hops].reverse(); // oldest first

  el.innerHTML = ordered.map((hop, i) => {
    const isOrigin = i === 0;
    const isLast   = i === ordered.length - 1;

    let delay = '';
    if (i > 0 && ordered[i - 1].ts && hop.ts) {
      const diff = Math.round((hop.ts - ordered[i - 1].ts) / 1000);
      const sign = diff >= 0 ? '+' : '';
      delay = `<span class="hop-delay">${sign}${diff}s</span>`;
    }

    const ipActions = hop.ip ? `
      <span class="hop-ip">
        ${esc(hop.ip)}
        <button class="hop-icon-btn" onclick="copyText('${esc(hop.ip)}')" title="Copy IP" aria-label="Copy IP">
          <svg width="10" height="10" viewBox="0 0 12 12" fill="none"><rect x="1" y="3" width="8" height="8" rx="1" stroke="currentColor" stroke-width="1.2"/><path d="M3 1h8v8" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
        </button>
        <a class="hop-enrich-link" href="https://h3ad-sec.github.io/X-VERDIKT/?ip=${encodeURIComponent(hop.ip)}" target="_blank" rel="noopener" title="Enrich in X-VERDIKT">X-VERDIKT ↗</a>
      </span>` : '';

    return `
      <div class="hop-node${isOrigin ? ' hop-origin' : ''}">
        <div class="hop-track">
          <div class="hop-dot"></div>
          ${!isLast ? '<div class="hop-line"></div>' : ''}
        </div>
        <div class="hop-body">
          <div class="hop-meta">
            <span class="hop-label">${isOrigin ? 'ORIGIN' : 'HOP ' + i}</span>
            ${ipActions}
            ${delay}
          </div>
          ${hop.from ? `<div class="hop-detail">from <span>${esc(hop.from)}</span></div>` : ''}
          ${hop.by ? `<div class="hop-detail muted">by <span>${esc(hop.by)}</span>${hop.proto ? ` · ${esc(hop.proto)}` : ''}</div>` : ''}
          ${hop.tsRaw ? `<div class="hop-ts">${esc(hop.tsRaw)}</div>` : ''}
        </div>
      </div>`;
  }).join('');
}

// ─── Header overview ───────────────────────────────────────────────────────────

function renderOverview(ov) {
  const rows = [
    ['FROM',         ov.from],
    ['TO',           ov.to],
    ['SUBJECT',      ov.subject],
    ['DATE',         ov.date],
    ['REPLY-TO',     ov.replyTo],
    ['RETURN-PATH',  ov.returnPath],
    ['MESSAGE-ID',   ov.messageId],
    ['X-MAILER',     ov.xMailer],
    ['CONTENT-TYPE', ov.contentType]
  ].filter(([, v]) => v);

  document.getElementById('overview-tbody').innerHTML = rows.map(([k, v]) =>
    `<tr><td class="ov-key">${k}</td><td class="ov-val">${esc(v)}</td></tr>`
  ).join('');
}

// ─── Sender analysis ───────────────────────────────────────────────────────────

function renderSenderAnalysis(r) {
  const fromDomain = r.fromInfo.domain;
  const rows = [
    { field: 'FROM',        addr: r.overview.from,       domain: r.fromInfo.domain },
    { field: 'REPLY-TO',    addr: r.overview.replyTo,    domain: r.replyToInfo.domain },
    { field: 'RETURN-PATH', addr: r.overview.returnPath, domain: r.returnPathInfo.domain },
    { field: 'MESSAGE-ID',  addr: r.overview.messageId,  domain: r.msgIdDomain }
  ].filter(row => row.addr || row.domain);

  document.getElementById('sender-tbody').innerHTML = rows.map(row => {
    const mismatch = row.domain && fromDomain && row.domain !== fromDomain && row.field !== 'FROM';
    return `
      <tr>
        <td class="sa-field">${row.field}</td>
        <td class="sa-addr">${esc(row.addr || '')}</td>
        <td class="sa-domain${mismatch ? ' sa-mismatch' : ''}">
          ${esc(row.domain || '')}
          ${mismatch ? '<span class="tag-mismatch">MISMATCH</span>' : ''}
        </td>
      </tr>`;
  }).join('');
}

// ─── Risk flags ────────────────────────────────────────────────────────────────

function renderRiskFlags(risks) {
  const el = document.getElementById('risk-flags');
  if (!risks.length) {
    el.innerHTML = '<p class="no-flags">No risk indicators detected.</p>';
    return;
  }
  el.innerHTML = risks.map((f, i) => `
    <div class="risk-item">
      <div class="risk-num">${String(i + 1).padStart(2, '0')}</div>
      <div class="risk-body">
        <div class="risk-title">
          <span class="risk-badge risk-${f.level}">${f.level.toUpperCase()}</span>
          ${esc(f.title)}
        </div>
        <div class="risk-detail">${esc(f.detail)}</div>
      </div>
    </div>`
  ).join('');
}

// ─── First hop ─────────────────────────────────────────────────────────────────

function renderFirstHop(ip) {
  const section = document.getElementById('first-hop-section');
  if (!ip) { section.style.display = 'none'; return; }
  section.style.display = '';
  document.getElementById('fh-ip').textContent = ip;
  document.getElementById('fh-enrich').onclick = () =>
    window.open(`https://h3ad-sec.github.io/X-VERDIKT/?ip=${encodeURIComponent(ip)}`, '_blank');
  document.getElementById('fh-copy').onclick = () => {
    copyText(ip);
    const btn = document.getElementById('fh-copy');
    btn.textContent = 'COPIED';
    setTimeout(() => btn.textContent = 'COPY', 1500);
  };
}

// ─── X-Spam ────────────────────────────────────────────────────────────────────

function renderXSpam(xSpam) {
  const card = document.getElementById('xspam-card');
  if (!xSpam) { card.style.display = 'none'; return; }
  card.style.display = '';

  const rows = [
    ['X-SPAM-FLAG',   xSpam.flag],
    ['X-SPAM-SCORE',  xSpam.score],
    ['X-SPAM-STATUS', xSpam.status]
  ].filter(([, v]) => v);

  document.getElementById('xspam-tbody').innerHTML = rows.map(([k, v]) =>
    `<tr><td class="ov-key">${k}</td><td class="ov-val">${esc(v)}</td></tr>`
  ).join('');
}

// ─── Raw headers ──────────────────────────────────────────────────────────────

function renderRaw(headers) {
  document.getElementById('raw-content').textContent =
    Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
}

function toggleRaw() {
  const content = document.getElementById('raw-content');
  const btn = document.getElementById('raw-toggle');
  const open = content.style.display !== 'none';
  content.style.display = open ? 'none' : 'block';
  btn.textContent = open ? 'EXPAND' : 'COLLAPSE';
}

// ─── Export / copy full analysis ──────────────────────────────────────────────

function copyAnalysis() {
  if (!_lastResult) return;
  const text = buildExportText(_lastResult);
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('copy-analysis-btn');
    btn.textContent = 'COPIED';
    setTimeout(() => btn.textContent = 'COPY ANALYSIS', 1500);
  }).catch(() => {});
}

function buildExportText(r) {
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  const lines = [];

  lines.push('MAILSCOPE ANALYSIS');
  lines.push('==================');
  lines.push(`Analyzed: ${now}`);
  lines.push('');

  // Verdict
  const high   = r.risks.filter(f => f.level === 'high').length;
  const medium = r.risks.filter(f => f.level === 'medium').length;
  const low    = r.risks.filter(f => f.level === 'low').length;
  const verdictLabel = high > 0 ? 'HIGH RISK' : medium > 0 ? 'MEDIUM RISK' : low > 0 ? 'LOW RISK' : 'CLEAN';
  lines.push(`VERDICT: ${verdictLabel} · ${r.risks.length} flag${r.risks.length !== 1 ? 's' : ''} (${high} high, ${medium} medium, ${low} low)`);
  lines.push('');

  // Auth
  lines.push('AUTH STATUS');
  lines.push(`  SPF:    ${(r.auth.spf || 'none').toUpperCase()}${r.auth.spfDomain ? '  ' + r.auth.spfDomain : ''}`);
  lines.push(`  DKIM:   ${(r.auth.dkim || 'none').toUpperCase()}${r.auth.dkimSelector ? '  selector: ' + r.auth.dkimSelector : ''}`);
  lines.push(`  DMARC:  ${(r.auth.dmarc || 'none').toUpperCase()}`);
  lines.push('');

  // Risk flags
  lines.push(`RISK FLAGS (${r.risks.length})`);
  if (r.risks.length) {
    r.risks.forEach((f, i) => {
      lines.push(`  ${String(i + 1).padStart(2, '0')} [${f.level.toUpperCase().padEnd(6)}]  ${f.title}`);
      lines.push(`             ${f.detail}`);
    });
  } else {
    lines.push('  None detected.');
  }
  lines.push('');

  // Hop chain
  const ordered = [...r.hops].reverse();
  const transitStr = r.transitSeconds !== null ? ` · ${formatTransit(r.transitSeconds)} transit` : '';
  lines.push(`HOP CHAIN (${r.hops.length} hop${r.hops.length !== 1 ? 's' : ''}${transitStr})`);
  ordered.forEach((hop, i) => {
    const label = i === 0 ? 'ORIGIN' : `HOP ${i}   `;
    const ip = hop.ip ? `  ${hop.ip}` : '  (no IP)';
    lines.push(`  ${label}${ip}  from ${hop.from || 'unknown'}`);
    if (hop.by) lines.push(`           by ${hop.by}${hop.proto ? ' via ' + hop.proto : ''}`);
    if (hop.tsRaw) lines.push(`           ${hop.tsRaw}`);
  });
  lines.push('');

  // Header overview
  lines.push('HEADER OVERVIEW');
  const ovFields = [
    ['FROM',        r.overview.from],
    ['TO',          r.overview.to],
    ['SUBJECT',     r.overview.subject],
    ['DATE',        r.overview.date],
    ['REPLY-TO',    r.overview.replyTo],
    ['RETURN-PATH', r.overview.returnPath],
    ['MESSAGE-ID',  r.overview.messageId],
    ['X-MAILER',    r.overview.xMailer]
  ].filter(([, v]) => v);
  ovFields.forEach(([k, v]) => lines.push(`  ${k.padEnd(12)}  ${v}`));
  lines.push('');

  // Sender analysis
  lines.push('SENDER ANALYSIS');
  const fromDomain = r.fromInfo.domain;
  [
    { field: 'FROM',        domain: r.fromInfo.domain },
    { field: 'REPLY-TO',    domain: r.replyToInfo.domain },
    { field: 'RETURN-PATH', domain: r.returnPathInfo.domain },
    { field: 'MESSAGE-ID',  domain: r.msgIdDomain }
  ].filter(row => row.domain).forEach(row => {
    const mismatch = row.domain && fromDomain && row.domain !== fromDomain && row.field !== 'FROM';
    lines.push(`  ${row.field.padEnd(14)}  ${row.domain}${mismatch ? '  [MISMATCH]' : ''}`);
  });
  lines.push('');

  if (r.firstHopIp) {
    lines.push(`ORIGIN IP: ${r.firstHopIp}`);
    lines.push('');
  }

  if (r.xSpam) {
    lines.push('SPAM FILTER');
    if (r.xSpam.flag)   lines.push(`  FLAG:    ${r.xSpam.flag}`);
    if (r.xSpam.score)  lines.push(`  SCORE:   ${r.xSpam.score}`);
    if (r.xSpam.status) lines.push(`  STATUS:  ${r.xSpam.status}`);
    lines.push('');
  }

  lines.push('-- Generated by MAILSCOPE / H3AD-SEC --');
  return lines.join('\n');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function copyText(str) {
  navigator.clipboard.writeText(String(str)).catch(() => {});
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
