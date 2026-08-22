# inboxproof-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js 18+](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![No dependencies](https://img.shields.io/badge/dependencies-none-blue.svg)](https://github.com/jtc268/inboxproof-cli)

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

Run it against any domain:

```
$ npx github:jtc268/inboxproof-cli example.com

Inboxproof deliverability audit: example.com
------------------------------------------------

  [FAIL] MX     No usable MX records found.
         fix: Add an MX record for example.com.
  [PASS] SPF    SPF: v=spf1 -all (ends with -all hardfail, strongest)
  [PASS] SPF limits 0 DNS lookup(s) (limit 10).
  [PASS] DKIM   DKIM (default): v=DKIM1; p=...
  [PASS] DMARC  DMARC: v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s
  [PASS] DMARC policy p=reject (strongest enforcement).
  [FAIL] PTR    Skipped (no MX host).
         fix: PTR is checked against the sending IP in the full audit.
  [FAIL] TLS    Skipped (no MX host).
         fix: SMTP STARTTLS is checked against the mail server in the full audit.

  Score: 60/100  (At risk)

  3 check(s) need attention.
  Full audit with TLS, IP reputation and per-check detail:
  https://inboxproof.email/
```

Every failing check prints the exact record to add or change. A healthy sending domain passes all eight checks and scores 100/100 (Healthy).

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

## How it compares

| Tool | What it does | Cost | Account |
|---|---|---|---|
| inboxproof-cli | 8 DNS checks, 0 to 100 score, exact fix | Free | None |
| MXToolbox | 20+ DNS checks, no score | Free | None |
| Mail-Tester | Full email test, 0 to 10 score | Free | None |
| GlockApps | Full email test, 0 to 100 score | Freemium | Yes |
| inboxproof (web) | 7 checks + IP reputation + fix guide | Free | None |

The CLI is the fastest way to check your mail config from your terminal or CI. The web audit adds IP reputation and a shareable fix guide.

## Security

The CLI is read-only. It sends DNS queries to your domain's nameservers and connects to your mail server on port 25 to check TLS. It never writes to your DNS, never stores your domain, and never sends your data to any third party.

The only network traffic is:
- DNS queries to your domain's nameservers (A, MX, TXT, NS records)
- A TCP connection to your mail server on port 25 (to check STARTTLS)

No telemetry, no analytics, no phone home.

## Support

If you are stuck, open an issue with the exact command you ran and the output you got. I read every issue.

You can also run the CLI against a known-good domain to verify it works:

```bash
npx github:jtc268/inboxproof-cli example.com
```

## Contributors

This project was built by the inboxproof team. If you have a feature request or a bug report, open an issue. If you want to contribute code, fork the repo and open a pull request.

## Report a problem

Found a domain it scores wrong, or a check that should be weighted differently? Open an issue:

https://github.com/jtc268/inboxproof-cli/issues

## Frequently asked questions

**Is it free?**
Yes. No account, no signup, no cost. It reads your live DNS only, so it is safe to run in CI and it changes nothing.

**Does it modify my DNS?**
No. It only reads your DNS records. It never writes anything.

**Can I use it in CI/CD?**
Yes. It exits 1 when the score is below a threshold, so you can fail a build the moment your mail config breaks. See the "Gate a deploy on deliverability" section above.

**Does it support subdomains?**
Yes. Run it against any domain, including subdomains: `npx github:jtc268/inboxproof-cli mail.example.com`.

**What does the score mean?**
The score is a weighted sum of the 8 checks. A score of 80 or higher is "Good" (B or better). Anything under 80 is flagged with the exact record to add or change.

## Roadmap

- **v1.2.0**: Add a `--watch` mode that re-checks your domain every N seconds and alerts when a record changes. Useful during DNS propagation.
- **v1.3.0**: Add a `--baseline` flag that saves your current score to a file and compares against it on subsequent runs. Useful for CI/CD.

Already shipped: `--json` (full audit as JSON) and `--threshold N` (minimum score for a passing exit code) are available now.

## Changelog

**v1.1.1** (2026-08-22)
- SPF check now collects all `v=spf1` TXT records, hard-fails the check when more than one exists (multiple SPF records are invalid), and notes the final qualifier (`-all` hardfail is strongest, `~all` softfail, none is least strict). Weights unchanged, so scores stay comparable.

**v1.1.0** (2026-08-22)
- Added SPF lookup limit check (flags SPF records with more than 10 DNS lookups)
- Added DMARC policy check (flags `p=none` as a warning)
- Added Troubleshooting section to README
- Added Contributing section to README
- Added FAQ section to README

**v1.0.0** (2026-08-15)
- Initial release with 6 checks: MX, SPF, DKIM, DMARC, PTR, TLS
- Score calculation and threshold gating
- JSON output for CI/CD pipelines

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

MIT. Use it, modify it, ship it. No strings attached.
