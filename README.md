# Assemblyline service: JoeSandboxV2

Shows [Joe Sandbox](https://www.joesandbox.com) results for files in Assemblyline 4.

The service looks up each file's SHA-256 and reports the newest finished analysis: verdict and
score, behaviour signatures (tagged as `dynamic.signature.name`), network activity (tagged as
`network.dynamic.*`), dropped files, and a link to the report. The verdict is also recorded as a
`Sandbox` part of the result ontology. A lookup sends only the hash. Files Joe Sandbox has never
seen produce an empty result.

## Which files are looked up

Scope is set by the `lookup_depth` and `extracted_types` submission options (see Settings).

Before SDK timeout retries, a lookup uses one API call for an unknown hash and two for a
finished report when search provides status and timestamp metadata. Missing metadata requires
up to five analysis-info calls, for a maximum of seven calls including the report download.
Skipped files cost nothing, and their empty results are not cached.

Lookup-only analyses still in progress show an unscored pending result with a report link.
Assemblyline does not cache that partial result or retry the task. A later submission can
fetch the finished report. Complete search metadata keeps this path to one API call.

A nonempty search with unresolved analysis statuses produces an unscored partial coverage
notice listing up to five candidate IDs and report links, newest first, and cannot trigger an
upload. Malformed reports or mismatched analysis IDs produce recoverable report errors.

## Daily API request quota

Daily API request limits from search, analysis-info, report download, upload or submission
status checks produce an unscored partial coverage notice and pause account lookups.
The task stops without further API calls or a recoverable retry. During the cooldown,
tasks make no Joe Sandbox calls.

If quota interrupts analysis-info or report retrieval, the result retains the candidate or
selected analysis's ID, report link and available timestamp. If Joe Sandbox has accepted an
upload, it also retains the public-upload notice and submission ID.

After `quota_cooldown_seconds` (default `3600`), the next task makes one recovery probe.
A successful lookup closes the cooldown; another daily-request quota response starts it again.
Only one probe runs at a time for an API endpoint and key within a worker process.
Separate worker processes have independent cooldowns. Changing the key or API URL selects a
separate cooldown; restarting the worker process clears its state. After a confirmed quota
reset, restart the worker process to probe sooner. The cooldown does not assume a quota reset
timezone or time of day.

Worker logs record the failing API phase when the cooldown opens or reopens, and record
successful recovery. Cooldown skips and tasks skipped during a recovery probe have distinct notices.

Temporary API failures still produce recoverable errors. Other permission errors do not
activate the daily-request cooldown.

## Uploading files

`submit_to_joesandbox` (default `false`) uploads the file only when the hash search returns no
matches. The service waits for the analysis and reports it like a lookup, noting that the file
was uploaded. Extracted files are uploaded only when `upload_extracted` is also `true`, within
the lookup scope above. Uploaded files are public.

- Uploads count against the account's quota (Cloud Basic: 5 per day, 10 per month).
- A refused upload, for example with the submission quota exhausted, shows Joe Sandbox's
  message in an unscored partial result.
- Status-check timeouts, server failures and permission errors stop polling immediately and
  produce recoverable errors with the submission ID.
- An analysis that does not finish within `submission_timeout` is retried by Assemblyline. The
  retry finds the analysis by hash and does not upload again.

A malformed upload reply fails immediately and warns that the file may already have been
uploaded. Malformed status replies and finished submissions without a valid analysis ID also
fail immediately, with the submission ID in the error. Finished submissions use the preferred
analysis or the first valid entry in the fallback analysis list.

## Heuristics

| ID | Name | Score | Raised when |
|----|------|-------|-------------|
| 1 | Malicious | 1000 | Joe Sandbox classified the file as malicious |
| 2 | Suspicious | 500 | Joe Sandbox classified the file as suspicious |
| 3 | Clean/Unknown | 0 | Joe Sandbox classified the file as clean or could not classify it |

## Installation and settings

In Assemblyline, open Administration → Services → Add service, paste `service_manifest.yml`,
then set `api_key` in the service settings.

### Settings

| Name | Scope | Default | Range | Effect |
|------|-------|---------|-------|--------|
| `api_key` | service setting | (empty) | | Joe Sandbox API key. Required. |
| `api_url` | service setting | `https://www.joesandbox.com/api/` | | API endpoint; change it for an on-premise Joe Sandbox. |
| `report_url` | service setting | `https://www.joesandbox.com/analysis/{webid}/0/html` | | Report link shown in results. |
| `submission_timeout` | service setting | `1200` | 60 to the manifest `timeout` minus 60 (1440) | Seconds to wait for an uploaded file's analysis. |
| `poll_interval` | service setting | `30` | 5 to 300 | Seconds between status checks while waiting. |
| `quota_cooldown_seconds` | service setting | `3600` | 0 to 86400 | Seconds to pause account lookups after the daily API request limit, before allowing one recovery probe. |
| `timeout` | service setting | `60` | 5 to 120 | Seconds before one Joe Sandbox API request times out. |
| `retries` | service setting | `3` | 0 to 10 | How often the API client retries a failed request. |
| `systems` | service setting | `w10x64` | | Comma-separated systems for uploads. Empty lets Joe Sandbox choose, which can pick a system a Cloud Basic account does not have. |
| `lookup_depth` | submission option | `6` | integer | Maximum extraction depth. `0` is the submitted file only, `1` adds files extracted from it, and `6` covers Assemblyline's default depth. |
| `extracted_types` | submission option | `.*` | regular expression | Matched from the start of an extracted file's type, for example `executable/.*\|document/.*\|code/.*`. The submitted file is always looked up. |
| `submit_to_joesandbox` | submission option | `false` | true or false | Upload a file that has no analysis. Uploaded files are public on Cloud Basic. |
| `upload_extracted` | submission option | `false` | true or false | Also upload extracted files in the lookup scope. Needs `submit_to_joesandbox`. |
| `systems` | submission option | (empty) | comma-separated names of 1 to 40 letters, digits, `_`, `.`, `-` | Systems for uploads from this submission. Empty uses the service setting. Invalid names are dropped and listed in a result section; if none are valid the service setting is used. Lookups ignore it. |

Out-of-range values are clamped and unusable values replaced by the default, each with one
warning in the service log. Changing any setting except `api_key` changes the service version
that Assemblyline uses for result caching, so earlier cached results are not reused.

A missing or rejected key fails each file without task retry, with an error naming the problem.

## Tests

```bash
bash scripts/build-image.sh al4-joesandbox:test 4.7.0.dev0 podman
bash scripts/ci-gate.sh al4-joesandbox:test podman
```

The gate runs Ruff, Pyright and pytest inside the image, offline, against recorded responses in
`tests/fixtures/jbx/`.

## Layout

```
joesandboxv2/
  analysis.py     lookup scope, picking the newest analysis, report parsing
  service.py      class JoeSandboxV2(ServiceBase)
tests/            tests, fake client, recorded responses, samples/ and results/
scripts/          build-image.sh, ci-gate.sh, gentests.py
```
