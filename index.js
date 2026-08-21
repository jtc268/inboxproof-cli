#!/usr/bin/env node
// inboxproof-cli: free command-line email deliverability audit.
// Checks MX, SPF, DKIM, DMARC, PTR and SMTP STARTTLS for a domain.
// Prints a spam-risk score and the exact record to fix.
// Full audit (TLS, IP reputation, per-check detail): https://inboxproof-phi.vercel.app/

import dns from 'node:dns';
import net from 'node:net';

const domain = (process.argv[2] || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
if (!domain || !/^[a-z0-9.-]+$/.test(domain)) {
  console.error('Usage: inboxproof <domain>');
  console.error('Example: inboxproof example.com');
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
    const spf = txt.flat().find(t => t.toLowerCase().startsWith('v=spf1'));
    if (spf) add('SPF', true, `SPF: ${spf}`);
    else add('SPF', false, 'No SPF record found.', `Add TXT: "v=spf1 include:_spf.google.com ~all" (adjust to your mail provider).`);
  } catch (e) {
    add('SPF', false, `SPF lookup failed: ${e.code || e.message}`, `Add an SPF TXT record for ${domain}.`);
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
  } catch (e) {
    add('DMARC', false, `DMARC lookup failed: ${e.code || e.message}`, `Add a DMARC TXT record at _dmarc.${domain}.`);
  }
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

const WEIGHTS = { MX: 25, SPF: 20, DKIM: 20, DMARC: 20, PTR: 5, TLS: 10 };

(async () => {
  console.log(`\nInboxproof deliverability audit: ${domain}\n` + '-'.repeat(48));
  const mxHosts = await checkMX();
  await checkSPF();
  await checkDKIM();
  await checkDMARC();
  await checkPTR(mxHosts);
  await checkTLS(mxHosts);

  let score = 0;
  for (const r of results) score += r.pass ? WEIGHTS[r.name] : 0;

  console.log('');
  for (const r of results) {
    const mark = r.pass ? 'PASS' : 'FAIL';
    console.log(`  [${mark}] ${r.name.padEnd(6)} ${r.detail}`);
    if (!r.pass && r.fix) console.log(`         fix: ${r.fix}`);
  }
  console.log('');
  const grade = score >= 80 ? 'Healthy' : score >= 50 ? 'At risk' : 'High spam risk';
  console.log(`  Score: ${score}/100  (${grade})`);
  const fails = results.filter(r => !r.pass).length;
  console.log(`\n  ${fails === 0 ? 'All checks passed.' : `${fails} check(s) need attention.`}`);
  console.log('  Full audit with TLS, IP reputation and per-check detail:');
  console.log('  https://inboxproof-phi.vercel.app/\n');
  process.exit(0);
})();
