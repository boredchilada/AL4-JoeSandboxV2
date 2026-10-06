# Assemblyline service: JoeSandboxV2

Shows [Joe Sandbox](https://www.joesandbox.com) results for files in Assemblyline 4.

The service looks up each file's SHA-256 and reports the newest finished analysis: verdict and
score, behaviour signatures (tagged as `dynamic.signature.name`), network activity (tagged as
`network.dynamic.*`), dropped files, and a link to the report. The verdict is also recorded as a
`Sandbox` part of the result ontology. A lookup sends only the hash. Files Joe Sandbox has never
seen produce an empty result.

## Which files are looked up

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `lookup_depth` | `6` | Maximum extraction depth. `0` is the submitted file only, `1` adds files extracted from it, and `6` covers Assemblyline's default depth. |
| `extracted_types` | `.*` | Regular expression matched from the start of an extracted file's type, for example `executable/.*\|document/.*\|code/.*`. The submitted file is always looked up. |

A lookup costs 1 API call for an unknown hash, normally 4 with a report, and at most 8.
Skipped files cost nothing, and their empty results are not cached.

## Uploading files

`submit_to_joesandbox` (default `false`) uploads the file when Joe Sandbox has no analysis of
it, finished or running. The service waits for the analysis and reports it like a lookup, noting
that the file was uploaded. Extracted files are uploaded only when `upload_extracted` is also
`true`, within the lookup scope above. Uploaded files are public.

- Uploads count against the account's quota (Cloud Basic: 5 per day, 10 per month).
- A refused upload, for example with the quota exhausted, shows Joe Sandbox's message.
- An analysis that does not finish within `submission_timeout` is retried by Assemblyline. The
  retry finds the analysis by hash and does not upload again.

## Heuristics

| ID | Name | Score | Raised when |
|----|------|-------|-------------|
| 1 | Malicious | 1000 | Joe Sandbox classified the file as malicious |
| 2 | Suspicious | 500 | Joe Sandbox classified the file as suspicious |
| 3 | Clean/Unknown | 0 | Joe Sandbox classified the file as clean or could not classify it |

## Installation and configuration

In Assemblyline, open Administration → Services → Add service, paste `service_manifest.yml`,
then set `api_key` in the service settings.

| Key | Default | Meaning |
|-----|---------|---------|
| `api_key` | (empty) | Joe Sandbox API key. Required. |
| `api_url` | `https://www.joesandbox.com/api/` | API endpoint; change it for an on-premise Joe Sandbox. |
| `report_url` | `https://www.joesandbox.com/analysis/{webid}/0/html` | Report link shown in results. |
| `submission_timeout` | `1200` | Seconds to wait for an uploaded file's analysis. |
| `poll_interval` | `30` | Seconds between status checks while waiting. |
| `systems` | `w10x64` | Comma-separated systems for uploads. Empty lets Joe Sandbox choose, which can pick a system a Cloud Basic account does not have. |

A missing or rejected key fails each file with an error naming the problem.

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
