# GitHub App PR summaries

ReviewBoundary can publish a comparison result as a GitHub App comment on a pull
request. It creates one App-owned result comment, updates that comment on later
runs, and leaves an identical result unchanged. The comment names the full
evaluated commit and shows bounded comparison counts. It does not post raw model
findings, grant a GitHub review approval, or merge a pull request.

This is a workflow-driven integration. It needs no hosted webhook receiver.
The code and registration template are available; **an App is not registered,
installed, or activated by installing the Python package**. Activation requires
the repository owner's GitHub setup and credentials described below. Tests use
generated test keys and mocked HTTP responses, not a live App.

## Register and install

The simplest setup is manual registration through GitHub's App settings:

1. Open your personal or organization's **Settings → Developer settings →
   GitHub Apps → New GitHub App**. You need permission to register an App for
   that account and approve its installation on the selected repository.
2. Choose a unique App name and set the homepage to this project's repository
   or your own integration documentation.
3. Disable **Webhooks → Active**. Do not subscribe to any events. No user OAuth
   flow, callback URL, or hosted application is needed for this publisher.
4. Grant **Repository permissions → Pull requests: Read and write**.
   GitHub supplies Metadata read access. Leave Checks, Contents, Actions, Issues,
   Administration, and organization/account permissions ungranted. PR comments
   support the Pull requests write permission. [GitHub comment API permissions](https://docs.github.com/en/rest/issues/comments#create-an-issue-comment)
5. Create the App, record its numeric **App ID**, and generate an RSA private
   key from the App settings. Keep the PEM outside the repository, with mode
   `0600`. Never commit it or copy it into an evaluation artifact.
6. Install the App on the intended account, choosing **Only select repositories**
   and the exact repository to receive results. Record the numeric installation
   ID shown in that installation's settings URL.
7. Add the App key to the trusted publication job's protected secret storage.
   Configure the App ID, installation ID, and exact repository allowlist in
   trusted workflow configuration. They must not come from a candidate PR or
   from the comparison artifact.

The [manifest template](../examples/github-app/manifest-template.json) expresses
the same minimal registration. Its inactive webhook includes a syntactically
valid placeholder URL because GitHub requires `hook_attributes.url` when that
object is supplied. `active: false` and an empty event list disable deliveries.
The placeholder is not a running service.

For an existing registration portal, submit this template through GitHub's
documented manifest flow with your own unique name, redirect endpoint, and
unguessable state. Complete the redirect and one-time code exchange within the
documented deadline, and store the resulting credentials securely. The JSON file
alone does not perform that handshake. Manual registration avoids needing a
registration portal. [GitHub manifest registration](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)

## Publish from a trusted job

Install the optional signing dependency:

```sh
uv sync --extra github
```

Copy the [configuration example](../examples/github-app/config.example.json) to
a trusted location outside the candidate checkout. Replace its placeholder
App ID, installation ID, absolute PEM path, and repository allowlist. This JSON
contains the key's path, not the key itself. Config files are limited to 16 KiB.

After producing a compatible baseline comparison, preview the exact comment
without credentials or network access:

```sh
uv run review-boundary github-preview \
  --repository YOUR_OWNER/YOUR_REPOSITORY \
  --pull-number 123 \
  --expected-head FULL_40_CHARACTER_EVALUATED_COMMIT_SHA \
  --comparison runs/comparison.json \
  --app-id YOUR_NUMERIC_APP_ID \
  --output runs/pr-comment.md
```

Omit `--output` to print the preview. An output file must be new; existing files
are preserved. To publish, use the trusted configuration and the PR head from
trusted run metadata:

```sh
uv run --extra github review-boundary github-publish \
  --repository YOUR_OWNER/YOUR_REPOSITORY \
  --pull-number 123 \
  --expected-head FULL_40_CHARACTER_EVALUATED_COMMIT_SHA \
  --comparison runs/comparison.json \
  --config /absolute/private/path/reporting-app.json
```

Each config allowlist entry is an exact `owner/repository` name; wildcards are rejected.
The example SHA and IDs are placeholders. Use the immutable evaluated commit,
not a branch name, a PR merge ref, or the publication job's own checkout SHA.
The comparison must come from the trusted evaluator for that commit. The
publisher validates its schema and internal counts, but cannot authenticate a
fabricated artifact's provenance by inspecting JSON alone.

Config and comparison inputs must be regular files. Symlinks, duplicate JSON
keys, non-finite numbers, and data exceeding the file limits are rejected. Both
commands exit `0` on success or `2` on invalid input or an operational error.
A successfully published regression still exits `0`: publication success is
separate from the comparison gate's pass/fail status. The comment states that
regressions were found, and the evaluation job retains its failing gate.

Keep evaluation and publication in separate jobs:

| Evaluation job | Publication job |
| --- | --- |
| Uses a pinned trusted harness to run the approved experiment | Uses a pinned trusted harness to validate and render the resulting comparison |
| May receive the provider key only for authorized model evaluation | Receives the App PEM only for publication; no model provider key |
| Never receives the App PEM or installation token | Never checks out, installs, imports, or executes candidate PR code |
| Emits bounded JSON artifacts and the immutable evaluated commit | Verifies artifact/run provenance, repository, PR number, and expected head from trusted workflow context |

Do not place the App key in a job that runs a reviewer executable supplied by a
PR, even if that executable is called an adapter. Do not execute PR-controlled
scripts in a privileged `pull_request_target` or `workflow_run` reporting job.
The supplied reusable workflow limits App reporting to same-repository PRs;
fork PR reporting is disabled. A custom fork workflow must independently decide
whether evaluation is allowed and which artifacts are accepted. The publication
module does not authorize fork execution or make an untrusted artifact trustworthy.

Serialize publication for each repository/PR with a workflow concurrency group.
Let an active publication finish so its token cleanup can run, and confirm the
expected head just before calling the CLI. Superseded evaluations can be cancelled
before publication. Exact workflow and action source revisions should remain under
review, including the harness code used by the publication job.

## What the publisher verifies

The publisher signs a short-lived App JWT with RS256, verifies the authenticated
App and repository installation, and requests an installation token for exactly
one repository with Pull requests write access. It then checks the token's
actual accessible repositories and permissions. Tokens are revoked at the end
when possible; the result reports `token_revoked: false` if revocation fails.
The token still has GitHub's bounded expiration and is never printed or saved.
[App JWT requirements](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app),
[installation token scope](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)

Before creating or editing a comment, it verifies that the PR is open in the
approved repository and its head exactly matches the expected SHA. It checks
again immediately before writing and after the API response. A stale result
detected before publication makes no comment mutation.

GitHub's comment API does not provide an atomic condition tying a comment write
to a PR head. If the head changes during that final API race, publication returns
`head_changed_after_publish` instead of success. A comment may already exist, but
its text explicitly identifies only the evaluated SHA. Rerun for the new head.
This is why the workflow should serialize publication and why a comment never
claims to be a merge approval or a current-head status check.

Idempotency uses a marker scoped to the App and PR. The marker alone is not
trusted: the author must match the numeric bot user obtained for the
authenticated App, have the Bot account type, and have no conflicting App
attribution. An existing comment is fetched and checked again before editing.
Copied markers in another person's comment cannot authorize an update.
[GitHub's App bot identity example](https://github.com/actions/create-github-app-token#configure-git-cli-for-an-apps-bot-user)

The publisher scans at most 500 comments. A full scan limit or duplicate App-owned
result comments causes an explicit error instead of creating another comment.
HTTP mutations are not automatically retried. After an ambiguous network failure,
inspect the PR or rerun: a completed earlier write can be found by its verified
marker.

## Bounded output and credentials

Only GitHub.com is supported. Requests go to the fixed HTTPS host
`api.github.com`; redirects and environment proxy configuration are not used.
API responses and comparison artifacts are limited to 2 MiB. Prepared comment
bodies are limited to 8 KiB. Normal publication has a 24-request budget, a
90-second operation deadline, and socket timeouts of at most 10 seconds. Token
revocation has a separate short cleanup budget.

Model and prompt labels are normalized to bounded inline-code text without
mentions, HTML, Markdown delimiters, or line breaks. Comments contain aggregate
counts and a static explanation, not raw findings, error messages, arbitrary
links, or report-supplied instructions. API errors contain a status or stable
error code; response bodies, key material, JWTs, and installation tokens are
withheld.

This protects the publisher's output path. It does not replace trusted workflow
configuration, protected credentials, or artifact provenance checks. Existing
baseline failures remain visible and a passing regression comparison is not a
safety certification.

## Python API and local preview

```python
import json
from pathlib import Path
from review_boundary.github_app import (
    GitHubAppConfig,
    PublishRequest,
    publish_pr_result,
    render_comment,
)

config = GitHubAppConfig(
    app_id=123456,
    installation_id=654321,
    private_key_path=Path("/private/path/reviewboundary-app.pem"),
    allowed_repositories=("YOUR_OWNER/YOUR_REPOSITORY",),
)
request = PublishRequest(
    repository="YOUR_OWNER/YOUR_REPOSITORY",
    pull_number=123,
    expected_head_sha="a" * 40,
    comparison=json.loads(Path("runs/comparison.json").read_text()),
)
print(render_comment(request, config.app_id))  # No credentials or network needed.

# This call creates or updates a PR comment when valid credentials are supplied.
result = publish_pr_result(config, request)
print(json.dumps(result.to_dict()))
```

The [configuration example](../examples/github-app/config.example.json) documents
both the Python configuration shape and the CLI's `--config` input. `PublishResult`
reports `created`, `updated`, or `unchanged`, the comment ID and generated GitHub
URL, the evaluated head SHA, and whether the token was revoked. No live App
registration, installation, or successful publication is claimed by the examples.
