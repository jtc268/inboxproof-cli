// Set GitHub topics on jtc268/inboxproof-cli for developer-search discoverability
const TOKEN = process.env.GH_TOKEN;
if (!TOKEN) { console.error('Set the GH_TOKEN environment variable (a PAT with repo scope) and re-run.'); process.exit(1); }
const topics = [
  'email', 'email-deliverability', 'deliverability', 'spf', 'dkim', 'dmarc',
  'mx', 'dns', 'smtp', 'tls', 'spam', 'email-security', 'audit', 'email-audit', 'cli',
  'nodejs', 'command-line', 'email-testing', 'dns-records', 'email-marketing',
];
const res = await fetch('https://api.github.com/repos/jtc268/inboxproof-cli/topics', {
  method: 'PUT',
  headers: { 'Accept': 'application/vnd.github+json', 'Authorization': `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ names: topics }),
});
console.log('PUT status:', res.status);
const j = await res.json().catch(() => ({}));
if (res.ok) {
  console.log('topics now:', (j.names || []).join(','));
} else {
  console.log('error:', JSON.stringify(j));
}
