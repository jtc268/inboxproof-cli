#!/usr/bin/env node
// inboxproof-cli: free command-line email deliverability audit.
// Checks MX, SPF, DKIM, DMARC, PTR and SMTP STARTTLS for a domain.
// Prints a spam-risk score and the exact record to fix.
// Full audit (TLS, IP reputation, per-check detail): https://inboxproof.email/?domain=<domain>

import dns from 'node:dns';
import net from 'node:net';

const args = process.argv.slice(2);
const jsonMode = args.includes('--json');
const thresholdIdx = args.indexOf('--threshold');
const threshold = thresholdIdx !== -1 ? parseInt(args[thresholdIdx + 1], 10) : null;
const domain = (args.find((a, i) => !a.startsWith('--') && (thresholdIdx === -1 || i !== thresholdIdx + 1)) || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
if (!domain || !/^[a-z0-9.-]+$/.test(domain)) {
  console.error('Usage: inboxproof <domain> [--json] [--threshold <0-100>]');
  console.error('Example: inboxproof example.com');
  console.error('Example: inboxproof example.com --json --threshold 80');
  process.exit(1);
}
if (threshold !== null && (isNaN(threshold) || threshold < 0 || threshold > 100)) {
  console.error('Error: --threshold must be a number between 0 and 100.');
  process.exit(1);
}

const results = [];
function add(name, pass, detail, fix) {
  results.push({ name, pass, detail, fix });
}

async function checkMX() {
  try {
    const mx = await dns.promises.resolveMx(domain);
    const hosts = mx.map(m => (m.exchange || '').replace(/\.$/, '')).filter(h => h.length > 0);
    if (hosts.length === 0) { add('MX', false, 'No usable MX records found.', `Add an MX record for ${domain}.`); return []; }
    add('MX', true, `${hosts.length} MX record(s): ${hosts.join(', ')}`);
    return hosts;
  } catch (e) {
    add('MX', false, `MX lookup failed: ${e.code || e.message}`, `Add an MX record for ${domain}.`);
    return [];
  }
}

async function checkSPF() {
  try {
    const txt = await dns.promises.resolveTxt(domain);
    const spfRecords = txt.flat().filter(t => t.toLowerCase().startsWith('v=spf1'));
    if (spfRecords.length > 1) {
      add('SPF', false, `${spfRecords.length} SPF records found. Multiple SPF records make the domain's SPF invalid.`, 'Delete all but one SPF TXT record.');
      return null;
    }
    const spf = spfRecords[0] || null;
    if (spf) {
      const q = spf.toLowerCase();
      let note = '';
      if (/-all\b/.test(q)) note = ' (ends with -all hardfail, strongest)';
      else if (/~all\b/.test(q)) note = ' (ends with ~all softfail; -all is stronger)';
      else note = ' (no -all/~all qualifier; add ~all or -all)';
      add('SPF', true, `SPF: ${spf}${note}`);
    } else {
      add('SPF', false, 'No SPF record found.', `Add TXT: "v=spf1 include:_spf.google.com ~all" (adjust to your mail provider).`);
    }
    return spf;
  } catch (e) {
    add('SPF', false, `SPF lookup failed: ${e.code || e.message}`, `Add an SPF TXT record for ${domain}.`);
    return null;
  }
}

// SPF allows at most 10 DNS lookups; more than that makes validation fail (permerror).
function countSpfLookups(spf) {
  const tokens = spf.toLowerCase().split(/\s+/);
  let count = 0;
  for (const t of tokens) {
    if (t.startsWith('include:') || t === 'a' || t.startsWith('a:') ||
        t === 'mx' || t.startsWith('mx:') ||
        t === 'ptr' || t.startsWith('ptr:') ||
        t.startsWith('exists:') || t.startsWith('redirect=')) {
      count++;
    }
  }
  return count;
}

function checkSPFLimits(spfRecord) {
  if (!spfRecord) return;
  const lookups = countSpfLookups(spfRecord);
  if (lookups > 10) {
    add('SPF limits', false, `${lookups} DNS lookups (SPF limit is 10). Validation will fail.`, 'Flatten the SPF record: reduce include/a/mx mechanisms to 10 or fewer.');
  } else {
    add('SPF limits', true, `${lookups} DNS lookup(s) (limit 10).`);
  }
}

async function checkDKIM() {
  const selectors = ['default', 'google', 's1', 'selector1', 'k1', 'mail', 'dkim', 'mandrill', 'sendgrid', 'amazonses'];
  for (const sel of selectors) {
    try {
      const txt = await dns.promises.resolveTxt(`${sel}._domainkey.${domain}`);
      const rec = txt.flat().find(t => t.toLowerCase().startsWith('v=dkim1'));
      if (rec) { add('DKIM', true, `DKIM (${sel}): ${rec.slice(0, 60)}...`); return; }
    } catch { /* try next selector */ }
  }
  add('DKIM', false, 'No DKIM record found for common selectors.', `Publish a DKIM TXT record at <selector>._domainkey.${domain} (your mail provider gives you the value).`);
}

async function checkDMARC() {
  try {
    const txt = await dns.promises.resolveTxt(`_dmarc.${domain}`);
    const rec = txt.flat().find(t => t.toLowerCase().startsWith('v=dmarc1'));
    if (rec) add('DMARC', true, `DMARC: ${rec}`);
    else add('DMARC', false, 'No DMARC record found.', `Add TXT at _dmarc.${domain}: "v=DMARC1; p=none; rua=mailto:dmarc@${domain}"`);
    return rec || null;
  } catch (e) {
    add('DMARC', false, `DMARC lookup failed: ${e.code || e.message}`, `Add a DMARC TXT record at _dmarc.${domain}.`);
    return null;
  }
}

// p=none only monitors; it does not enforce. Flag it so the user knows the policy is weak.
function checkDMARCPolicy(dmarcRecord) {
  if (!dmarcRecord) return;
  const m = dmarcRecord.toLowerCase().match(/p=(none|quarantine|reject)/);
  if (!m) {
    add('DMARC policy', false, 'No p= tag found in the DMARC record.', 'Add a p= tag: p=none (monitor), p=quarantine, or p=reject.');
    return;
  }
  const policy = m[1];
  if (policy === 'reject') add('DMARC policy', true, 'p=reject (strongest enforcement).');
  else if (policy === 'quarantine') add('DMARC policy', true, 'p=quarantine (good enforcement).');
  else add('DMARC policy', false, 'p=none (monitor only, no enforcement).', 'Move to p=quarantine or p=reject once you have confirmed your legitimate mail passes.');
}

async function checkPTR(mxHosts) {
  if (mxHosts.length === 0) { add('PTR', false, 'Skipped (no MX host).', 'PTR is checked against the sending IP in the full audit.'); return; }
  try {
    const ptr = await dns.promises.reverse(mxHosts[0]);
    add('PTR', true, `PTR for ${mxHosts[0]}: ${Array.isArray(ptr) ? ptr[0] : ptr}`);
  } catch {
    add('PTR', false, `No PTR (reverse DNS) for ${mxHosts[0]}.`, 'Ensure your mail server IP has a matching PTR record.');
  }
}

function checkTLS(mxHosts) {
  return new Promise((resolve) => {
    if (mxHosts.length === 0) { add('TLS', false, 'Skipped (no MX host).', 'SMTP STARTTLS is checked against the mail server in the full audit.'); resolve(); return; }
    const host = mxHosts[0];
    const socket = net.createConnection({ host, port: 25, timeout: 6000 });
    let buf = '';
    let settled = false;
    const finish = (pass, detail) => { if (settled) return; settled = true; socket.destroy(); add('TLS', pass, detail); resolve(); };
    socket.on('connect', () => { socket.write('HELP\r\n'); });
    socket.on('data', (d) => {
      buf += d.toString();
      if (/STARTTLS/i.test(buf)) finish(true, `STARTTLS advertised by ${host}:25`);
      else if (/^(220|250)\b/m.test(buf) && buf.length > 40) finish(false, `${host}:25 reachable but no STARTTLS advertised.`);
    });
    socket.on('timeout', () => finish(false, `Timed out connecting to ${host}:25`));
    socket.on('error', (e) => finish(false, `Could not reach ${host}:25 (${e.code || e.message})`));
    setTimeout(() => finish(false, `Timed out checking STARTTLS on ${host}:25`), 8000);
  });
}

const WEIGHTS = { MX: 25, SPF: 15, 'SPF limits': 5, DKIM: 20, DMARC: 15, 'DMARC policy': 5, PTR: 5, TLS: 10 };

(async () => {
  const mxHosts = await checkMX();
  const spfRecord = await checkSPF();
  checkSPFLimits(spfRecord);
  await checkDKIM();
  const dmarcRecord = await checkDMARC();
  checkDMARCPolicy(dmarcRecord);
  await checkPTR(mxHosts);
  await checkTLS(mxHosts);

  let score = 0;
  for (const r of results) score += r.pass ? WEIGHTS[r.name] : 0;

  const passThreshold = threshold === null || score >= threshold;

  if (jsonMode) {
    const out = {
      domain,
      score,
      grade: score >= 80 ? 'healthy' : score >= 50 ? 'at-risk' : 'high-spam-risk',
      threshold: threshold,
      pass: passThreshold,
      checks: results.map(r => ({ name: r.name, pass: r.pass, detail: r.detail, fix: r.fix || null })),
      fullAudit: 'https://inboxproof.email/?domain=' + encodeURIComponent(domain) + '&ref=cli'
    };
    console.log(JSON.stringify(out, null, 2));
    process.exit(passThreshold ? 0 : 1);
  }

  console.log(`\nInboxproof deliverability audit: ${domain}\n` + '-'.repeat(48));
  console.log('');
  for (const r of results) {
    const mark = r.pass ? 'PASS' : 'FAIL';
    console.log(`  [${mark}] ${r.name.padEnd(6)} ${r.detail}`);
    if (!r.pass && r.fix) console.log(`         fix: ${r.fix}`);
  }
  console.log('');
  const grade = score >= 80 ? 'Healthy' : score >= 50 ? 'At risk' : 'High spam risk';
  console.log(`  Score: ${score}/100  (${grade})`);
  if (threshold !== null) {
    console.log(`  Threshold: ${threshold}/100  ${passThreshold ? '(PASS)' : '(FAIL)'}`);
  }
  const fails = results.filter(r => !r.pass).length;
  console.log(`\n  ${fails === 0 ? 'All checks passed.' : `${fails} check(s) need attention.`}`);
  console.log('  Full audit with TLS, IP reputation and per-check detail:');
  console.log('  https://inboxproof.email/?domain=' + encodeURIComponent(domain) + '&ref=cli\n');
  process.exit(passThreshold ? 0 : 1);
})();
