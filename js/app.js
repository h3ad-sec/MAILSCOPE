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
ARC-Seal: i=1; a=rsa-sha256; cv=none; d=mx.corp-mail.com; s=arc-2026;
        b=abc123fakesignaturedata==
ARC-Authentication-Results: i=1; mx.corp-mail.com;
        spf=fail smtp.mailfrom=support@paypal-secure.net;
        dkim=fail header.d=paypal-secure.net;
        dmarc=fail header.from=paypal.com
From: "PayPal Security Team" <security@paypal-secure.net>
Reply-To: harvest2026@gmail.com
To: employee@corp-mail.com
Delivered-To: employee@corp-mail.com
X-Original-To: bulk-target@corp-mail.com
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

const HISTORY_KEY = 'mailscope_history';
const HISTORY_MAX = 5;

let _lastResult = null;

// ─── Init ─────────────────────────────────────────────────────────────────────

document.getElementById('ms-input').addEventListener('input', function () {
  const val = this.value.trim();
  document.getElementById('analyze-btn').disabled = !val;
  updateHeaderCountChip(val ? this.value.split('\n').filter(l => l.trim()).length : 0);
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
  updateHeaderCountChip(SAMPLE.split('\n').filter(l => l.trim()).length);
}

function clearAll() {
  document.getElementById('ms-input').value = '';
  document.getElementById('analyze-btn').disabled = true;
  document.getElementById('results-section').style.display = 'none';
  document.getElementById('copy-analysis-row').style.display = 'none';
  document.getElementById('empty-state').style.display = '';
  updateHeaderCountChip(0);
  _lastResult = null;
}

function updateHeaderCountChip(count) {
  const chip = document.getElementById('header-count-chip');
  if (!chip) return;
  if (count > 0) {
    chip.textContent = count + ' lines';
    chip.style.display = 'inline';
  } else {
    chip.style.display = 'none';
  }
}

// ─── History ──────────────────────────────────────────────────────────────────

function saveHistory(r) {
  const high = r.risks.filter(f => f.level === 'high').length;
  const med  = r.risks.filter(f => f.level === 'medium').length;
  const entry = {
    ts: Date.now(),
    from:    r.overview.from    || '(unknown)',
    subject: r.overview.subject || '(no subject)',
    verdict: high > 0 ? 'high' : med > 0 ? 'medium' : r.risks.length > 0 ? 'low' : 'clean',
    hops:  r.hops.length,
    flags: r.risks.length
  };
  let hist = loadHistory();
  hist.unshift(entry);
  hist = hist.slice(0, HISTORY_MAX);
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(hist)); } catch (_) {}
  renderHistory(hist);
}

function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (_) { return []; }
}

function clearHistory() {
  try { localStorage.removeItem(HISTORY_KEY); } catch (_) {}
  renderHistory([]);
}

function renderHistory(hist) {
  const el = document.getElementById('history-list');
  if (!el) return;
  hist = hist || loadHistory();
  if (!hist.length) {
    el.innerHTML = '<div class="hist-empty">No recent analyses.</div>';
    return;
  }
  el.innerHTML = hist.map(entry => {
    const fromShort = entry.from.length > 34    ? entry.from.slice(0, 32) + '…' : entry.from;
    const subShort  = entry.subject.length > 38 ? entry.subject.slice(0, 36) + '…' : entry.subject;
    return `
      <div class="hist-item">
        <div class="hist-row">
          <span class="hist-verdict hist-v-${entry.verdict}">${entry.verdict.toUpperCase()}</span>
          <span class="hist-meta">${entry.hops}h &middot; ${entry.flags}f</span>
          <span class="hist-ago">${formatAgo(entry.ts)}</span>
        </div>
        <div class="hist-from">${esc(fromShort)}</div>
        <div class="hist-subject">${esc(subShort)}</div>
      </div>`;
  }).join('');
}

function formatAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)    return 'just now';
  if (s < 3600)  return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

// ─── Analysis ─────────────────────────────────────────────────────────────────

function runAnalysis() {
  const raw = document.getElementById('ms-input').value.trim();
  if (!raw) return;
  try {
    const r = MailParser.analyze(raw);
    _lastResult = r;
    renderAll(r);
    saveHistory(r);
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('results-section').style.display = 'flex';
    document.getElementById('copy-analysis-row').style.display = '';
  } catch (err) {
    console.error('MAILSCOPE error:', err);
  }
}

// ─── Render ───────────────────────────────────────────────────────────────────

function renderAll(r) {
  renderVerdict(r.risks, r.auth);
  renderAuth(r.auth);
  renderARC(r.arc);
  renderHopChain(r.hops, r.transitSeconds);
  renderOverview(r.overview);
  renderSenderAnalysis(r);
  renderRiskFlags(r.risks);
  renderFirstHop(r.firstHopIp, r);
  renderXSpam(r.xSpam);
  renderRaw(r.allHeaders);

  const high = r.risks.filter(f => f.level === 'high').length;
  document.getElementById('stat-hops').textContent    = r.hops.length || '0';
  document.getElementById('stat-flags').textContent   = r.risks.length || '0';
  document.getElementById('stat-high').textContent    = high || '0';
  document.getElementById('stat-transit').textContent = formatTransit(r.transitSeconds);
}

function formatTransit(s) {
  if (s === null) return 'N/A';
  if (s < 60)    return s + 's';
  if (s < 3600)  return Math.round(s / 60) + 'm';
  return Math.round(s / 3600) + 'h';
}

// ─── Verdict banner ───────────────────────────────────────────────────────────

function renderVerdict(risks, auth) {
  const el = document.getElementById('verdict-banner');
  const high   = risks.filter(f => f.level === 'high').length;
  const medium = risks.filter(f => f.level === 'medium').length;
  const low    = risks.filter(f => f.level === 'low').length;

  let level, label;
  if (high > 0)        { level = 'high';   label = 'HIGH RISK'; }
  else if (medium > 0) { level = 'medium'; label = 'MEDIUM RISK'; }
  else if (low > 0)    { level = 'low';    label = 'LOW RISK'; }
  else                 { level = 'clean';  label = 'CLEAN'; }

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

// ─── Auth ─────────────────────────────────────────────────────────────────────

function authClass(val) {
  if (val === 'pass')     return 'auth-pass';
  if (val === 'fail')     return 'auth-fail';
  if (val === 'softfail') return 'auth-warn';
  return 'auth-none';
}

function renderAuth(auth) {
  document.getElementById('auth-badges').innerHTML = [
    { key: 'spf',   label: 'SPF' },
    { key: 'dkim',  label: 'DKIM' },
    { key: 'dmarc', label: 'DMARC' }
  ].map(({ key, label }) => {
    const val = auth[key] || 'none';
    let sub = '';
    if (key === 'dkim'  && auth.dkimSelector) sub = `<span class="auth-sub">sel: ${esc(auth.dkimSelector)}</span>`;
    if (key === 'spf'   && auth.spfDomain)    sub = `<span class="auth-sub">${esc(auth.spfDomain)}</span>`;
    if (key === 'dmarc' && auth.dmarcPolicy)  sub = `<span class="auth-sub">policy: ${esc(auth.dmarcPolicy)}</span>`;
    return `
      <div class="auth-badge ${authClass(val)}">
        <span class="auth-proto">${label}</span>
        <span class="auth-val">${val.toUpperCase()}</span>
        ${sub}
      </div>`;
  }).join('');
}

// ─── ARC chain ────────────────────────────────────────────────────────────────

function renderARC(arc) {
  const card = document.getElementById('arc-card');
  if (!card) return;
  if (!arc || !arc.instances || !arc.instances.length) {
    card.style.display = 'none';
    return;
  }
  card.style.display = '';

  const finalCV = arc.finalCV || 'none';
  const cvLabel = finalCV === 'pass' ? 'PASS' : finalCV === 'fail' ? 'FAIL' : finalCV.toUpperCase();
  document.getElementById('arc-meta').textContent =
    `${arc.instances.length} instance${arc.instances.length !== 1 ? 's' : ''} · cv=${cvLabel}`;

  document.getElementById('arc-body').innerHTML = arc.instances.map(inst => {
    const cv     = (inst.cv || 'none').toUpperCase();
    const cvCls  = inst.cv === 'pass' ? 'arc-pass' : inst.cv === 'fail' ? 'arc-fail' : 'arc-none';
    const spfCls  = inst.spf  === 'pass' ? 'arc-pass' : 'arc-fail';
    const dkimCls = inst.dkim === 'pass' ? 'arc-pass' : 'arc-fail';
    const dmCls   = inst.dmarc=== 'pass' ? 'arc-pass' : 'arc-fail';
    return `
      <div class="arc-instance">
        <div class="arc-inst-num">i=${inst.instance}</div>
        <div class="arc-inst-cv ${cvCls}">cv=${cv}</div>
        <div class="arc-inst-auth">
          ${inst.spf   && inst.spf   !== 'none' ? `<span class="arc-proto">SPF <span class="${spfCls}">${inst.spf.toUpperCase()}</span></span>` : ''}
          ${inst.dkim  && inst.dkim  !== 'none' ? `<span class="arc-proto">DKIM <span class="${dkimCls}">${inst.dkim.toUpperCase()}</span></span>` : ''}
          ${inst.dmarc && inst.dmarc !== 'none' ? `<span class="arc-proto">DMARC <span class="${dmCls}">${inst.dmarc.toUpperCase()}</span></span>` : ''}
        </div>
      </div>`;
  }).join('');
}

// ─── Hop chain ────────────────────────────────────────────────────────────────

function renderHopChain(hops, transitSeconds) {
  const el      = document.getElementById('hop-chain');
  const titleEl = document.getElementById('hop-chain-meta');

  if (titleEl) {
    titleEl.textContent = transitSeconds !== null
      ? `${hops.length} hop${hops.length !== 1 ? 's' : ''} · ${formatTransit(transitSeconds)} transit`
      : `${hops.length} hop${hops.length !== 1 ? 's' : ''}`;
  }

  if (!hops.length) {
    el.innerHTML = '<p class="no-data">No Received headers found.</p>';
    return;
  }

  const ordered = [...hops].reverse();

  el.innerHTML = ordered.map((hop, i) => {
    const isOrigin = i === 0;
    const isLast   = i === ordered.length - 1;

    let delay = '';
    if (i > 0 && ordered[i - 1].ts && hop.ts) {
      const diff = Math.round((hop.ts - ordered[i - 1].ts) / 1000);
      delay = `<span class="hop-delay">${diff >= 0 ? '+' : ''}${diff}s</span>`;
    }

    let ipActions = '';
    if (hop.ip) {
      const safeIp = esc(hop.ip);
      ipActions = `
        <span class="hop-ip">
          ${safeIp}
          <button class="hop-icon-btn" onclick="copyText('${safeIp}')" title="Copy IP" aria-label="Copy IP">
            <svg width="10" height="10" viewBox="0 0 12 12" fill="none"><rect x="1" y="3" width="8" height="8" rx="1" stroke="currentColor" stroke-width="1.2"/><path d="M3 1h8v8" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
          </button>
          <a class="hop-enrich-link" href="https://h3ad-sec.github.io/X-VERDIKT/?ip=${encodeURIComponent(hop.ip)}" target="_blank" rel="noopener">X-VERDIKT ↗</a>
        </span>`;
    } else if (hop.from) {
      const host = extractHostname(hop.from);
      if (host) {
        ipActions = `<a class="hop-enrich-link" href="https://h3ad-sec.github.io/DNSCOPE/?q=${encodeURIComponent(host)}" target="_blank" rel="noopener">DNSCOPE ↗</a>`;
      }
    }

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
          ${hop.by   ? `<div class="hop-detail muted">by <span>${esc(hop.by)}</span>${hop.proto ? ` · ${esc(hop.proto)}` : ''}</div>` : ''}
          ${hop.tsRaw ? `<div class="hop-ts">${esc(hop.tsRaw)}</div>` : ''}
        </div>
      </div>`;
  }).join('');
}

function extractHostname(str) {
  const m = str.match(/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)/);
  return m ? m[1] : null;
}

// ─── Header overview ──────────────────────────────────────────────────────────

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

// ─── Sender analysis ──────────────────────────────────────────────────────────

function renderSenderAnalysis(r) {
  const fromDomain = r.fromInfo.domain;
  const toDomain   = r.toInfo ? r.toInfo.domain : null;

  const rows = [
    { field: 'FROM',          addr: r.overview.from,               domain: r.fromInfo.domain },
    { field: 'TO',            addr: r.overview.to,                 domain: toDomain },
    { field: 'REPLY-TO',      addr: r.overview.replyTo,            domain: r.replyToInfo.domain },
    { field: 'RETURN-PATH',   addr: r.overview.returnPath,         domain: r.returnPathInfo.domain },
    { field: 'MESSAGE-ID',    addr: r.overview.messageId,          domain: r.msgIdDomain },
    { field: 'DELIVERED-TO',  addr: r.overview.deliveredTo || '',  domain: extractEmailDomain(r.overview.deliveredTo) },
    { field: 'X-ORIGINAL-TO', addr: r.overview.xOriginalTo || '',  domain: extractEmailDomain(r.overview.xOriginalTo) }
  ].filter(row => row.addr || row.domain);

  document.getElementById('sender-tbody').innerHTML = rows.map(row => {
    let tag = '';
    if (row.domain && fromDomain && row.domain !== fromDomain && row.field !== 'FROM') {
      tag = '<span class="tag-mismatch">MISMATCH</span>';
    }
    if ((row.field === 'DELIVERED-TO' || row.field === 'X-ORIGINAL-TO') && toDomain && row.domain && row.domain !== toDomain) {
      tag = '<span class="tag-mismatch">ENVELOPE MISMATCH</span>';
    }
    return `
      <tr>
        <td class="sa-field">${row.field}</td>
        <td class="sa-addr">${esc(row.addr || '')}</td>
        <td class="sa-domain${tag ? ' sa-mismatch' : ''}">
          ${esc(row.domain || '')}
          ${tag}
        </td>
      </tr>`;
  }).join('');
}

function extractEmailDomain(str) {
  if (!str) return null;
  const m = str.match(/@([\w.\-]+)/);
  return m ? m[1] : null;
}

// ─── Risk flags ───────────────────────────────────────────────────────────────

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

// ─── First hop callout ────────────────────────────────────────────────────────

function renderFirstHop(ip, r) {
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
  const phishBtn = document.getElementById('fh-phishops');
  if (phishBtn && r) {
    phishBtn.onclick = () => openPhishOps(r.overview.subject, r.overview.from, ip);
  }
}

// ─── X-Spam ───────────────────────────────────────────────────────────────────

function renderXSpam(xSpam) {
  const card = document.getElementById('xspam-card');
  if (!xSpam) { card.style.display = 'none'; return; }
  card.style.display = '';

  document.getElementById('xspam-tbody').innerHTML = [
    ['X-SPAM-FLAG',   xSpam.flag],
    ['X-SPAM-SCORE',  xSpam.score],
    ['X-SPAM-STATUS', xSpam.status]
  ].filter(([, v]) => v).map(([k, v]) =>
    `<tr><td class="ov-key">${k}</td><td class="ov-val">${esc(v)}</td></tr>`
  ).join('');
}

// ─── Raw headers ─────────────────────────────────────────────────────────────

function renderRaw(headers) {
  document.getElementById('raw-content').textContent =
    Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
}

function toggleRaw() {
  const content = document.getElementById('raw-content');
  const btn     = document.getElementById('raw-toggle');
  const open    = content.style.display !== 'none';
  content.style.display = open ? 'none' : 'block';
  btn.textContent = open ? 'EXPAND' : 'COLLAPSE';
}

// ─── PHISHOPS handoff ─────────────────────────────────────────────────────────

function openPhishOps(subject, sender, ip) {
  const params = new URLSearchParams();
  if (subject) params.set('subject', subject);
  if (sender)  params.set('sender', sender);
  if (ip)      params.set('ip', ip);
  const qs = params.toString();
  window.open(`https://h3ad-sec.github.io/PHISHOPS/${qs ? '?' + qs : ''}`, '_blank');
}

// ─── Export ───────────────────────────────────────────────────────────────────

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
  const L = [];

  L.push('MAILSCOPE ANALYSIS');
  L.push('==================');
  L.push(`Analyzed: ${now}`);
  L.push('');

  const high   = r.risks.filter(f => f.level === 'high').length;
  const medium = r.risks.filter(f => f.level === 'medium').length;
  const low    = r.risks.filter(f => f.level === 'low').length;
  L.push(`VERDICT: ${high > 0 ? 'HIGH RISK' : medium > 0 ? 'MEDIUM RISK' : low > 0 ? 'LOW RISK' : 'CLEAN'} · ${r.risks.length} flag${r.risks.length !== 1 ? 's' : ''} (${high} high, ${medium} med, ${low} low)`);
  L.push('');

  L.push('AUTH STATUS');
  L.push(`  SPF:    ${(r.auth.spf   || 'none').toUpperCase()}${r.auth.spfDomain    ? '  ' + r.auth.spfDomain : ''}`);
  L.push(`  DKIM:   ${(r.auth.dkim  || 'none').toUpperCase()}${r.auth.dkimSelector ? '  selector: ' + r.auth.dkimSelector : ''}`);
  L.push(`  DMARC:  ${(r.auth.dmarc || 'none').toUpperCase()}${r.auth.dmarcPolicy  ? '  policy: ' + r.auth.dmarcPolicy : ''}`);
  L.push('');

  if (r.arc && r.arc.instances && r.arc.instances.length) {
    L.push(`ARC CHAIN (${r.arc.instances.length} instance${r.arc.instances.length !== 1 ? 's' : ''} · finalCV=${r.arc.finalCV || 'none'})`);
    r.arc.instances.forEach(inst => {
      const parts = [`i=${inst.instance}`, `cv=${inst.cv || 'none'}`];
      if (inst.spf   && inst.spf   !== 'none') parts.push(`spf=${inst.spf}`);
      if (inst.dkim  && inst.dkim  !== 'none') parts.push(`dkim=${inst.dkim}`);
      if (inst.dmarc && inst.dmarc !== 'none') parts.push(`dmarc=${inst.dmarc}`);
      L.push('  ' + parts.join(' · '));
    });
    L.push('');
  }

  L.push(`RISK FLAGS (${r.risks.length})`);
  if (r.risks.length) {
    r.risks.forEach((f, i) => {
      L.push(`  ${String(i + 1).padStart(2, '0')} [${f.level.toUpperCase().padEnd(6)}]  ${f.title}`);
      L.push(`             ${f.detail}`);
    });
  } else {
    L.push('  None detected.');
  }
  L.push('');

  const ordered    = [...r.hops].reverse();
  const transitStr = r.transitSeconds !== null ? ` · ${formatTransit(r.transitSeconds)} transit` : '';
  L.push(`HOP CHAIN (${r.hops.length} hop${r.hops.length !== 1 ? 's' : ''}${transitStr})`);
  ordered.forEach((hop, i) => {
    const label = i === 0 ? 'ORIGIN  ' : `HOP ${i}   `;
    L.push(`  ${label}${hop.ip ? '  ' + hop.ip : '  (no IP)'}  from ${hop.from || 'unknown'}`);
    if (hop.by)    L.push(`             by ${hop.by}${hop.proto ? ' via ' + hop.proto : ''}`);
    if (hop.tsRaw) L.push(`             ${hop.tsRaw}`);
  });
  L.push('');

  L.push('HEADER OVERVIEW');
  [['FROM', r.overview.from], ['TO', r.overview.to], ['SUBJECT', r.overview.subject],
   ['DATE', r.overview.date], ['REPLY-TO', r.overview.replyTo], ['RETURN-PATH', r.overview.returnPath],
   ['MESSAGE-ID', r.overview.messageId], ['X-MAILER', r.overview.xMailer]]
    .filter(([, v]) => v)
    .forEach(([k, v]) => L.push(`  ${k.padEnd(12)}  ${v}`));
  L.push('');

  L.push('SENDER ANALYSIS');
  const fromDomain = r.fromInfo.domain;
  [{ field: 'FROM',          domain: r.fromInfo.domain },
   { field: 'REPLY-TO',      domain: r.replyToInfo.domain },
   { field: 'RETURN-PATH',   domain: r.returnPathInfo.domain },
   { field: 'MESSAGE-ID',    domain: r.msgIdDomain },
   { field: 'DELIVERED-TO',  domain: extractEmailDomain(r.overview.deliveredTo) },
   { field: 'X-ORIGINAL-TO', domain: extractEmailDomain(r.overview.xOriginalTo) }]
    .filter(row => row.domain)
    .forEach(row => {
      const mismatch = row.domain && fromDomain && row.domain !== fromDomain && row.field !== 'FROM';
      L.push(`  ${row.field.padEnd(16)}  ${row.domain}${mismatch ? '  [MISMATCH]' : ''}`);
    });
  L.push('');

  if (r.firstHopIp) { L.push(`ORIGIN IP: ${r.firstHopIp}`); L.push(''); }

  if (r.xSpam) {
    L.push('SPAM FILTER');
    if (r.xSpam.flag)   L.push(`  FLAG:    ${r.xSpam.flag}`);
    if (r.xSpam.score)  L.push(`  SCORE:   ${r.xSpam.score}`);
    if (r.xSpam.status) L.push(`  STATUS:  ${r.xSpam.status}`);
    L.push('');
  }

  L.push('-- Generated by MAILSCOPE / H3AD-SEC --');
  return L.join('\n');
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

// ─── Boot ─────────────────────────────────────────────────────────────────────

(function init() {
  renderHistory();
})();
