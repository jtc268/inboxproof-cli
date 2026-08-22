# inboxproof-cli

Free command-line email deliverability audit. Point it at any domain and get a 0 to 100 spam-risk score plus the exact DNS record to fix. No account, no signup, no cost, no dependencies. It reads your live DNS only, so it is safe to run in CI and it changes nothing.

Run it straight from GitHub:

```
npx github:jtc268/inboxproof-cli example.com
```

Or clone and run it directly:

```
git clone https://github.com/jtc268/inboxproof-cli
cd inboxproof-cli
node index.js example.com
```

## What it checks

| Check | Weight | What it looks for |
|-------|--------|-------------------|
| MX         | 25     | A working MX record so mail has somewhere to land |
| SPF        | 15     | A `v=spf1` TXT record authorizing your senders |
| SPF limits | 5      | SPF stays under the 10 DNS-lookup limit (more fails validation) |
| DKIM       | 20     | A `v=dkim1` TXT record at a common selector |
| DMARC      | 15     | A `v=DMARC1` TXT record at `_dmarc.domain` |
| DMARC policy | 5    | A `p=` enforcement tag that is not just `p=none` |
| PTR        | 5      | Reverse DNS (PTR) on the mail server host |
| TLS   | 10     | SMTP STARTTLS advertised on port 25 |

Each check is weighted into a 0 to 100 score. Anything under 80 is flagged with the exact record to add or change.

## Gate a deploy on deliverability

The CLI exits 1 when the score is below a threshold, so you can fail a build the moment your mail config breaks:

```
npx github:jtc268/inboxproof-cli yourdomain.com --threshold 80
```

For JSON output (CI/CD pipelines, scripting, dashboards):

```
npx github:jtc268/inboxproof-cli yourdomain.com --json
```

### GitHub Actions

Run the audit on every push and block the deploy if the score drops:

```yaml
name: email-deliverability
on: [push]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Audit mail DNS
        run: npx github:jtc268/inboxproof-cli yourdomain.com --threshold 80
```

## Example output

```
$ npx github:jtc268/inboxproof-cli example.com

  example.com  ·  score 85/100  ·  B (Good)

  ✓ MX            mx.example.com (10)
  ✓ SPF           v=spf1 mx -all
  ✓ SPF limits    2 lookups (limit 10)
  ✓ DKIM          selector=mail, key found
  ✓ DMARC         v=DMARC1 p=reject
  ✓ DMARC policy  p=reject
  ✓ PTR           mx.example.com -> mail.example.com
  ✓ TLS           STARTTLS advertised on port 25

  All checks passed. Your domain is inbox-ready.
```

A failing domain shows the exact record to fix:

```
  ✕ DMARC         no _dmarc.example.com TXT record
      fix: add TXT record at _dmarc.example.com:
      v=DMARC1 p=none pct=100 rua=mailto:dmarc@example.com
```

## Troubleshooting

**"No MX record found"**
Your domain has no MX record. Add one pointing to your mail server. Most ESPs (SendGrid, Mailgun, Postmark, etc.) provide the exact record to add.

**"SPF record not found"**
Your domain has no SPF record. Add a TXT record with `v=spf1` and the senders you authorize. Most ESPs provide the exact record.

**"SPF lookup limit exceeded"**
Your SPF record has more than 10 DNS lookups. This is a hard limit in the SPF spec. Simplify your SPF record by using `include:` for shared services or by listing only the senders you actually use.

**"DKIM record not found"**
Your domain has no DKIM record. Add a TXT record at `<selector>._domainkey.domain` with the public key from your ESP. Common selectors: `mail`, `default`, `k1`, `s1`, `s2`.

**"DMARC record not found"**
Your domain has no DMARC record. Add a TXT record at `_dmarc.domain` with `v=DMARC1 p=none` to start. You can tighten the policy later.

**"No PTR record"**
Your mail server has no reverse DNS (PTR) record. This is usually set by your hosting provider or ESP. If you control the IP, add a PTR record pointing to your mail server hostname.

**"TLS not advertised"**
Your mail server does not advertise STARTTLS on port 25. This is usually a server configuration issue. If you use an ESP, they should handle TLS. If you self-host, enable STARTTLS in your MTA configuration.

## Why

Most email that lands in spam (or the provider's blacklist) fails one of these checks. This tool tells you which one in about ten seconds, from your terminal, with the exact fix.

## Full audit

The CLI covers the DNS layer. For the complete picture, TLS handshake detail, sending-IP reputation, and a step-by-step fix guide you can share with whoever manages your DNS, use the free web audit:

https://inboxproof.email/

## Report a problem

Found a domain it scores wrong, or a check that should be weighted differently? Open an issue:

https://github.com/jtc268/inboxproof-cli/issues

## Requirements

Node.js 18 or later. No dependencies.

## Contributing

Found a bug, or want to add a new check? Open an issue first so we can discuss the approach. Then:

1. Fork the repo and create a branch from `master`.
2. Run the CLI against a known-good domain to make sure your local copy works: `node index.js example.com`.
3. Make your change. Keep the no-dependencies promise: no `npm install` required.
4. Open a PR with a short description of what the check does and why it matters.

The codebase is a single `index.js` file. Each check is a function that returns `{ pass, detail, fix }`. The score is a weighted sum of the checks.

## License

MIT
