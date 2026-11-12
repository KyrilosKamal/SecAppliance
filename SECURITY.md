# Security Policy

## Supported versions
Only the latest release receives security fixes.

## Reporting a vulnerability
Please do not open a public issue. Use GitHub's **Report a vulnerability** button
(Security tab, private advisory) or email kyrillos.kamal@proton.me.
Include affected version, reproduction steps and impact. You will get an
acknowledgement within 7 days.

## Scope notes
- SecAppliance is an active scanner. Use it only on systems you own or are explicitly authorized to test.
- By default it contacts the CIRCL CVE API with product/version strings taken from service banners. Use `--offline` to disable this.
- Credentials are never accepted as CLI arguments (`SECAPPLIANCE_PASSWORD` env var or hidden prompt).
