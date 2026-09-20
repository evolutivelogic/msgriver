# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability
reporting for this repository. Include affected versions, a minimal reproduction, impact, and any
known mitigation. Maintainers will acknowledge the report and coordinate disclosure after a fix is
available.

## Supported versions

No software version has been released yet. The `main` branch may receive security fixes, but it is not
a supported distribution until the first published pre-release. Published support windows will be
defined before the first stable release.

## Operational boundary

MsgRiver deliberately creates outbound effects. Operators remain responsible for provider
credentials, authorized destinations, network egress policy, payload retention, and access to the
local socket or remote API. Never include a real secret in a bug report.
