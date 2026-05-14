---
name: custom-domain-carded-io-cutover
description: Cut Carded over from the default *.onrender.com domain to a custom domain (carded.io or fallback). Add the custom domain in Render, configure Cloudflare DNS, verify TLS, and live-smoke-test.
type: feature
status: open
---

# Feature — Custom Domain Cutover (carded.io)

## Background

Phase 5 deployed Carded to Render and is live on a `*.onrender.com` URL. Graham confirmed end-to-end functionality on that URL but deferred the custom-domain step to ship faster.

The Phase 5 runbook (`.cursor/docs/2-phase-5-deployment-runbook.md` § "Step 3 — Cloudflare DNS cutover") already contains the operator steps for this. This feature exists to track the work as a discrete unit.

## Acceptance criteria

- [ ] `carded.io` is registered (or a fallback: `carded.app`, `getcarded.io`, etc.).
- [ ] Custom domain added in Render dashboard → service → Settings → Custom Domains. Both apex (`carded.io`) and `www.carded.io` if desired.
- [ ] Cloudflare DNS configured:
  - Apex (`@`): CNAME → `<service>.onrender.com` (Cloudflare apex-CNAME flattening). DNS-only (gray cloud) initially for cert issuance.
  - `www`: CNAME → `<service>.onrender.com`. DNS-only initially.
- [ ] Render shows the domain as **Verified** and TLS cert as **Issued**.
- [ ] (Optional) Flip Cloudflare proxy to orange-cloud once cert issues — purely a CDN/WAF preference, not required.
- [ ] Live smoke test from the custom domain:
  - `curl -fsS https://carded.io/health` → `{"status":"ok"}`
  - `GET https://carded.io/` → 200 with rendered HTML
  - Full browser test on the custom domain: BYOK key entry, real card upload, vCard download, Google CSV download.
  - iOS Safari test (HEIC upload from camera roll) + Android Chrome test.

## Out of scope

- Migrating off Cloudflare for DNS.
- Adding a CDN tier in front of Render (orange-cloud flip is optional, not required).
- Email / MX records for `carded.io`.

## Dependencies

- None — the app is already live on `*.onrender.com`. This is additive.

## Estimated effort

~30–60 minutes once the domain is registered and you're sitting at the Cloudflare + Render dashboards. Most of the time is waiting for DNS propagation and cert issuance (typically 1–5 min on Cloudflare).

## References

- `.cursor/docs/2-phase-5-deployment-runbook.md` § "Step 3 — Cloudflare DNS cutover" — full step-by-step operator instructions.
- `.cursor/progress/2-carded-mvp-plan-final.md` § "Phase 5 — Deployment" — original plan.
