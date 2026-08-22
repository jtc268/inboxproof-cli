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
| MX    | 25     | A working MX record so mail has somewhere to land |
| SPF   | 20     | A `v=spf1` TXT record authorizing your senders |
| DKIM  | 20     | A `v=dkim1` TXT record at a common selector |
| DMARC | 20     | A `v=DMARC1` TXT record at `_dmarc.domain` |
| PTR   | 5      | Reverse DNS (PTR) on the mail server host |
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

## License

MIT
