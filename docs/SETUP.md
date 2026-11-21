# Setting up the pipeline in your own GitHub account

About 30 minutes of clicking, plus 20 to 30 minutes for the first release to
run. You need `git` and the [GitHub CLI](https://cli.github.com/), logged in
with `gh auth login`. When it asks, choose **HTTPS** and answer **Yes** to
"Authenticate Git with your GitHub credentials": GitHub does not accept an
account password for `git push`, and this makes git use the CLI's token.

Order matters. Settings go in **before** the first push, because the first
push to `main` starts a release.

## 1. Create an empty repository

```sh
export OWNER=your-github-username
gh repo create "$OWNER/pihole-hardened" --public \
  --description "Hardened, signed Pi-hole image for Raspberry Pi with SBOMs and compliance evidence"
```

Public is recommended. Nothing in the repository is secret, Pis can pull the
image without credentials, and Scorecard can publish results. GitHub's arm64
runners also work in private repositories, but with fewer vCPUs.

## 2. Repository settings

Run these from any directory:

```sh
R="$OWNER/pihole-hardened"
# GITHUB_TOKEN read-only by default; workflows request what they need per job
gh api -X PUT "repos/$R/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
# Renovate merges its own PRs once checks pass
gh repo edit "$R" --enable-auto-merge --delete-branch-on-merge
# Private vulnerability reporting (SECURITY.md points here)
gh api -X PUT "repos/$R/private-vulnerability-reporting"
```

Then in the web UI (`https://github.com/$OWNER/pihole-hardened/settings`):

1. **Actions → General → Actions permissions:** choose the option that allows
   your own actions plus selected others. Tick *Allow actions created by
   GitHub* (this covers `actions/*` and `github/codeql-action`), and in the
   list of specified actions enter
   `docker/*, sigstore/*, anchore/*, ossf/*, step-security/*, hadolint/*, zizmorcore/*`.
   Tick **Require actions to be pinned to a full-length commit SHA**, then
   **Save**.
2. **General → Releases:** tick **Enable release immutability**. It only
   applies to releases created afterwards, so do it now. The workflow uploads
   every asset when it creates a release, so immutability doesn't get in the
   way.
3. **Environments → New environment:** name it `production`. Under
   **Deployment branches and tags**, choose *Selected branches and tags* and
   add `main`. Don't add required reviewers: that would make releases wait
   for a person.

## 3. Push the code

From the unpacked repository folder:

```sh
cd pihole-hardened
# put your account name into the deploy files and README
grep -rl 'OWNER/pihole-hardened' --exclude-dir=.git --exclude=SETUP.md . | xargs sed -i "s#OWNER/pihole-hardened#$OWNER/pihole-hardened#g"
git init -b main
git add -A
git commit -m "Hardened Pi-hole image, pipeline, lab and compliance bundle"
git remote add origin "https://github.com/$OWNER/pihole-hardened.git"
git push -u origin main
```

On macOS, use `sed -i ''` instead of `sed -i`.

If the push fails:

- *"Password authentication is not supported"* or *"Invalid username or
  token"*: git is not using the CLI's login. Run `gh auth setup-git` and push
  again.
- *"refusing to allow an OAuth App to create or update workflow"*: the token
  lacks the `workflow` scope, which a push containing `.github/workflows/`
  needs. Run `gh auth refresh -h github.com -s workflow` and push again.

## 4. Watch the first release

The push starts `release.yml`:

```sh
gh run watch -R "$OWNER/pihole-hardened" "$(gh run list -R "$OWNER/pihole-hardened" --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Expect about 30 minutes. The slowest parts are the emulated armv7 build and
the two lab runs, which run in parallel. A few things happen for the first
time here:

- The first push to GHCR creates the package as **private**, linked to the
  repository. Until you make it public (step 5), a host can only pull it
  after `docker login ghcr.io` with a token that has `read:packages`.
- The arm64 lab job is the first runtime test on ARM.
- Lab variants V07 and V08 show as skipped on GitHub's runners ("host port
  53 in use"), because the runner's DNS stub already uses port 53. The lab
  report then reads "7 pass, 0 fail, 2 skipped" and the verdict is still
  PASS. Both variants pass when the lab runs on a host with port 53 free.

If a job fails, nothing is published, and an issue titled "Release pipeline
failing" links to the run.

## 5. After the first successful release

1. **Make the image public** so Pis can pull without credentials:
   `https://github.com/users/$OWNER/packages/container/pihole-hardened/settings`
   → **Change visibility** → Public.
2. **Protect `main`:** **Settings → Rules → Rulesets → New ruleset → New
   branch ruleset**.
   - Name: `main`. Enforcement: Active. Target: the default branch.
   - Rules: *Restrict deletions*; *Block force pushes*; *Require a pull
     request before merging* with 0 required approvals (a higher number would
     stop Renovate merging its own PRs); *Require status checks to pass* with
     `lint`, `smoke (amd64)` and `smoke (arm64)`.
3. **Install Renovate:** `https://github.com/apps/renovate` → Install → Only
   select repositories → `pihole-hardened`. The repository already has
   `renovate.json`, so Renovate skips onboarding. Check the *Dependency
   Dashboard* issue it opens: it should list the four Pi-hole releases,
   Alpine, Trivy, ORAS and the actions.
4. **Verify the release from your machine** (needs `cosign` 3.x, `curl`, `jq`):
   ```sh
   scripts/verify-release.sh "$OWNER/pihole-hardened" latest
   ```

## 6. Deploy to the Pi

Follow *Deploy on a Raspberry Pi* in the README. From then on, the pipeline
runs without you:

- Renovate opens PRs for upstream releases, base image digests and action
  updates. Pi-hole releases, Alpine patch releases and digest refreshes, and
  non-major action updates merge automatically once CI passes. Trivy and ORAS
  updates, a new Alpine minor version and major action updates wait for your
  review.
- Every merge that changes the pins, the Dockerfile, scripts, lab, VEX or
  workflows, and every Monday, the release workflow builds, scans, lab-tests
  and publishes. A change to documentation or `deploy/` alone does not start
  a release.
- The Pi's timer verifies and installs the newest release, rolling back if
  it isn't healthy.

Your remaining manual jobs: review Trivy and ORAS updates (Renovate bumps the
version; you verify and update the two tarball hashes in `upstream.env`, for
Trivy ideally against a second channel such as the
`ghcr.io/aquasecurity/trivy` image); review VEX pull requests; when a
release's `vulnerability-report.md` lists a CVE in an embedded library that
`vex/EMBEDDED-TRIAGE.md` doesn't cover, judge it and add it there; handle a
"Release pipeline failing" issue if one appears. One of its causes is deliberate: the release refuses to publish when
an upstream tag or the FTL release asset changed content without changing its
name, because that is what a replaced upstream release looks like.

After the first few releases, read Harden-Runner's egress audit in the job
logs and switch `egress-policy` from `audit` to `block` with an
`allowed-endpoints` list; the workflows ship in audit mode because the
endpoint list is only known once they have run.

## 7. Publish to Docker Hub as well (optional)

The release workflow can copy every release to Docker Hub. It is the same
image, not a rebuild: the index digest is identical on both registries, and
the signatures, SBOM/vulnerability/VEX attestations and provenance are copied
with it, so `cosign verify` works against either name. The copy happens in
the `publish release` job, after the scan, lab and drift gates, and the
workflow verifies the signatures on the Docker Hub copy before it moves
`latest` on either registry. It runs on the same schedule as everything else:
every Monday 06:17 UTC and after every merged update.

Nothing happens until you set the `DOCKERHUB_IMAGE` variable, so a repository
without it behaves exactly as before.

1. **Create the Docker Hub repository** `pihole-hardened` (public) under your
   account or organization at <https://hub.docker.com/repositories>. Creating
   it yourself, instead of letting the first push create it, lets you set the
   visibility and description first.
2. **Create an access token:** Docker Home (<https://app.docker.com>) → avatar
   → **Account settings** → **Personal access tokens** → **Generate new
   token**. Repository permission **Read & Write** (not Delete). Give it an
   expiry and put the date in your calendar: when it lapses the release fails
   and opens the "Release pipeline failing" issue, nothing worse. A personal
   token covers every repository in your account; if the repository lives in
   a Docker organization, use an organization access token limited to this
   one repository instead.
3. **Store it in the `production` environment, not as a repository secret.**
   The environment is limited to `main`, so only the publish job on `main`
   can read it:

   ```sh
   gh secret set DOCKERHUB_TOKEN --env production -R "$OWNER/pihole-hardened"   # paste the token
   gh variable set DOCKERHUB_USERNAME -R "$OWNER/pihole-hardened" --body "your-docker-id"
   gh variable set DOCKERHUB_IMAGE    -R "$OWNER/pihole-hardened" --body "your-docker-id/pihole-hardened"
   ```
4. **Run a release** (or wait for Monday):
   `gh workflow run release.yml -R "$OWNER/pihole-hardened"`. Then check from
   your machine that the copy verifies:

   ```sh
   IMAGE_REPO=docker.io/your-docker-id/pihole-hardened \
     scripts/verify-release.sh "$OWNER/pihole-hardened" latest
   ```
5. **Optional, on Docker Hub:** repository **Settings → General → Tag
   mutability settings → Specific tags are immutable** with the pattern
   `.*-h[0-9]+$`. That locks the per-release tags (`2026.10.1-h42`) while
   `latest` and the upstream-version tag keep moving. The feature is in beta;
   if re-running a failed publish job is ever rejected because the tag
   already exists, start a new run instead.

**Docker organizations on a Team or Business plan** can avoid the stored
token: create an OIDC connection (Docker Home → organization → **Identity &
auth** → **OIDC connections**) with the subject
`repo:OWNER/pihole-hardened:environment:production` (the publish job runs in
the `production` environment, so GitHub puts the environment, not the branch,
in the token's subject). Set the variable `DOCKERHUB_OIDC_CONNECTION_ID` to
the connection ID, `DOCKERHUB_USERNAME` to the organization name, and delete
the `DOCKERHUB_TOKEN` secret. Personal accounts and free organizations can't
use this.

People who only want to run the image can use
`deploy/docker-compose.dockerhub.yml`: one self-contained file with the same
hardening, pulling `docker.io/OWNER/pihole-hardened:latest` (the `sed` in
step 3 fills in `OWNER`; edit it if your Docker ID differs from your GitHub
account). CI keeps it identical to `deploy/docker-compose.yml` apart from the
image line.

To have a Pi pull from Docker Hub instead of GHCR with verification, set
`IMAGE_REPO=docker.io/your-docker-id/pihole-hardened` for `update.sh` (there
is a commented line for it in `pihole-update.service`). The updater still
reads the signed release from GitHub and only accepts a registry copy that
release names. Anonymous Docker Hub pulls are rate-limited per IP address;
one daily pull by digest is far below the limit.

Two things to know:

- GitHub pauses scheduled workflows in a public repository after 60 days
  without repository activity. Renovate's merges normally count; if upstream
  is quiet for two months, GitHub emails you and one click re-enables it.
- ORAS (the tool that copies the image) is pinned by hash in `upstream.env`
  like Trivy, so its updates wait for your review too.
