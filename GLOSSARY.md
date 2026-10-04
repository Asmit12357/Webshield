# Glossary

Domain terms used in WebShield. Use these names in code, tests and reviews.

- **Target**: the website address a visitor asks WebShield to scan. Only public hosts on port 80 or 443 are valid targets, and every redirect hop must pass the same rule.
- **Scan**: one run of all checks against a target, stored with its score, grade and findings.
- **Check**: one test of a target (for example HSTS). It returns a finding with a status of pass, warn, fail or na, and a weight in points.
- **Finding**: the result of one check: status, points earned, points available, evidence and a fix.
- **Scored / not scored**: a check with 0 points available (n/a, or informational such as Permissions-Policy) is not scored and never changes the score.
- **Score**: points earned divided by points available, out of 100. A rejected TLS certificate caps it at 50.
- **Network**: the one place the scan engine reaches the outside world: single-hop HTTP requests, the TLS handshake and DNS. The real network is one adapter; a scripted site used by tests is the other.
- **Scoring version**: version 1 scans only checked that a header existed; version 2 grades the header values. Only version 2 scans are comparable.
