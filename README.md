# inboxproof-cli

Free command-line email deliverability audit. Run it against any domain and get a spam-risk score plus the exact DNS record to fix. No account, no signup, no cost.

Run it straight from GitHub:

```
$ npx github:jtc268/inboxproof-cli example.com
```

Or clone and run it directly:

```
$ git clone https://github.com/jtc268/inboxproof-cli
$ cd inboxproof-cli
$ node index.js example.com
```

For JSON output (CI/CD pipelines, scripting):

```
$ npx github:jtc268/inboxproof-cli example.com --json
```

## What it checks

| Check | What it looks for |
|-------|-------------------|
| MX    | A working MX record so mail has somewhere to land |
| SPF   | A `v=spf1` TXT record authorizing your senders |
| DKIM  | A `v=dkim1` TXT record at a common selector |
| DMARC | A `v=DMARC1` TXT record at `_dmarc.domain` |
| PTR   | Reverse DNS (PTR) on the mail server host |
| TLS   | SMTP STARTTLS advertised on port 25 |

Each check is weighted into a 0-100 score. Anything under 80 is flagged with the exact record to add.

## Why

Most email that lands in spam (or the provider's blacklist) fails one of these checks. This tool tells you which one in about ten seconds, from your terminal.

## Full audit

The CLI covers the DNS layer. For the complete picture, TLS handshake detail, sending-IP reputation, and a step-by-step fix guide, use the free web audit:

https://inboxproof-phi.vercel.app/

## Requirements

Node.js 18 or later. No dependencies.

## License

MIT
