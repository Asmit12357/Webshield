# WebShield

#### Video Demo: <add your URL here>

#### Description

WebShield is a web application that audits the security configuration of any public website. You enter an address
such as `github.com`; WebShield fetches the site, inspects how it is configured, and returns a score out of 100, a
letter grade (A+ to F), and a list of findings. Each finding shows the evidence WebShield saw and, when something
is wrong, a "How to fix" snippet. Every audit is saved, so you can reopen it later and compare sites in the history
page.

It is built with Flask, SQLite and the `requests` library, with Bootstrap and a custom stylesheet for the interface.
It can run locally or on Vercel.

## What it checks

| Check | Points | Passes when |
|---|---|---|
| HTTPS | 15 | The final page is served over HTTPS and the certificate was accepted |
| TLS certificate | 15 | A full-verification handshake succeeds; shows issuer, expiry and TLS version (warns under 14 days left or on TLS 1.0/1.1) |
| HTTP → HTTPS redirect | 5 | `http://` redirects to `https://` (follows up to 3 hops) |
| HSTS | 15 | `max-age` is at least 180 days (shorter warns, `max-age=0` fails) |
| Content-Security-Policy | 15 | Present and free of `unsafe-inline`, `unsafe-eval` and `*` in `default-src` / `script-src` |
| Clickjacking protection | 5 | `X-Frame-Options: DENY/SAMEORIGIN` or CSP `frame-ancestors` |
| MIME sniffing protection | 5 | `X-Content-Type-Options` is exactly `nosniff` |
| Referrer-Policy | 5 | Present and not `unsafe-url` / `no-referrer-when-downgrade` |
| Cookie security | 10 | Every first-party cookie, across all redirects, has `Secure` and (for session-like names) `HttpOnly`; `SameSite` is preferred |
| Server information leakage | 10 | No `X-Powered-By`-style headers and no version numbers in `Server` |
| Mixed content | 5 | A HTTPS page does not load scripts, images or frames over HTTP |
| Permissions-Policy | 0 | Informational only |

**Scoring.** Score = points earned ÷ points available × 100. A check that does not apply (for example, a site that
sets no cookies) is marked N/A and excluded rather than given free points. A rejected TLS certificate caps the score
at 50. `X-XSS-Protection` is deliberately not scored: modern browsers removed the feature it controls.

## Safety of the scanner itself

Because WebShield makes requests on behalf of whoever uses it, it protects itself:

- Only ports 80 and 443 are allowed, and URLs with embedded credentials are refused.
- The hostname is resolved and refused if any address is private, loopback, link-local or otherwise non-public
  (this blocks `127.0.0.1`, `169.254.169.254` cloud-metadata addresses, internal networks, etc.).
- Redirects are followed manually, and every hop is validated again.
- Requests have timeouts and the whole scan has a 15-second budget.
- Scans are rate-limited to 10 per minute per client. The limiter lives in memory, so on a serverless host it is
  per instance, not global.

Known limitation: the address is checked before connecting, not pinned, so a hostile DNS server that changes its
answer between the check and the request could in theory bypass it.

## Project structure

| File | Role |
|---|---|
| `app.py` | Flask routes (`/`, `/scan/<id>`, `/history`), database setup and migration, rate limiting |
| `pycheck.py` | The scan engine: input validation, fetching, and every check |
| `score.py` | Turns check results into a score and a grade |
| `templates/` | Jinja templates for the scanner, result and history pages |
| `public/static/style.css`, `public/static/app.js` | The one copy of the assets: Vercel serves `public/` from its CDN and Flask serves the same folder locally. The stylesheet is split into ordered `@layer`s; `app.js` is optional progressive enhancement driven by `data-` attributes |
| `api/index.py`, `vercel.json` | Entry point and routing for Vercel |
| `tests/` | pytest suite (checks, scoring, app behavior); no network needed |
| `record.sql` | Reference copy of the database schema |

### Design decisions

- **Every check returns the same structure** (`status`, `points`, `max`, `evidence`, `fix`), so adding a check means
  writing one function and appending it to `run_checks`; the template and scoring pick it up automatically.
- **Results are stored as JSON** next to the score, so an old audit can be reopened exactly as it was shown, and
  rescoring rules can change without losing the evidence. Rows from before this change (`score_version = 1`) were
  scored by the old presence-only rules and show a notice instead of details.
- **Post/redirect/get:** a scan redirects to `/scan/<id>`, so refreshing the page does not run the scan again.

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000.

To run the tests:

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Deploying to Vercel

The project is configured for Vercel (`vercel.json` + `api/index.py`). Vercel's filesystem is read-only apart from
`/tmp`, so history is stored in a temporary SQLite file that **resets when the function restarts**. The history page
says so when running on Vercel. For permanent history, move the `scans` table to a hosted database.
