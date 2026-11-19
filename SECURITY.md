# Security policy

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting: the
**Security** tab of this repository, then **Report a vulnerability**. Don't
open a public issue, pull request or discussion for it.

Include what an attacker can do, the steps or a proof of concept, and the
commit you tested. The conversation continues in the report.

## Scope

`main` is the only supported version. In scope: this program and its image,
including how it writes private keys and certificates and how it talks to
the ACME server. A vulnerability in the ACME server, in the web server that
answers the challenges, or in a particular deployment's configuration
belongs to their maintainers.
