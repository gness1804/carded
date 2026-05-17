---
github_issue: 11
---
# Render Is Not Picking Up New Commits For This Project

## Working directory

`~/Desktop/carded`

## Contents

Render should be automatically picking up new commits for this project. Currently on a feature branch to build out the MVP for the site. This feature branch is noted as the working branch in render. However, when I push up a new commit, it does nothing. I have to manually run a deploy in order to get the new commit actually deployed. 

Refer to the instructions in this Claude Code session: claude --resume 443a3bff-791b-453e-910f-f3a69896139f

## Acceptance criteria

- Pushing up a new commit will cause render to automatically redeploy the site.

## Resolution (2026-05-17)

**Root cause:** The Render GitHub App had lost access to the `carded` repo. The
service was configured correctly (branch = `master`, Auto-Deploy = "On Commit"),
but Render was never receiving push events from GitHub, so auto-deploy had
nothing to trigger on. The Events tab confirmed it: the last delivered event
was the MVP-scaffold merge on 2026-05-14 at 18:51, and every commit to `master`
after that was silently missed.

The empty repo-level `Settings → Webhooks` list was a red herring — Render
delivers push events via its GitHub App, not classic webhooks, so the absence
of repo-scoped webhooks is normal.

**Fix:** Added `carded` to the Render GitHub App's repository access list at
<https://github.com/settings/installations>. No code change required.

<!-- DONE -->
