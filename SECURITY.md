# Security policy

## Reporting a vulnerability

**In this repository** (the Dockerfile, workflows, scripts or deployment
files): use GitHub's private vulnerability reporting, under this repository's
**Security** tab → **Report a vulnerability**. Please don't open a public
issue.

**In Pi-hole itself** (FTL, the web interface, the core scripts or upstream's
startup scripts): report it to the Pi-hole project privately, following their
security policy (disclosure@pi-hole.net). Fixes flow into this image through
the next upstream release.

## Supported versions

Only the latest release is supported. Releases are rebuilt at least weekly,
so deploy by digest from the newest release (see `scripts/verify-release.sh`).

## Accepting a vulnerability

A finding the scanners report but that doesn't affect this image is
documented in `vex/pihole.openvex.json` through a reviewed pull request, with
a justification. Scanner-specific ignores in `.trivyignore` need a reason and
an expiry date.
