# JoeSandboxV2 API request optimization

Owner: JoeSandboxV2 maintainer. Reader: fleet operator and service implementer. Purpose: reduce lookup requests while retaining nested-payload coverage and keeping uploads off.

## Decision

Prioritize quota handling, then reuse search metadata. Keep fleet `deep_scan=true`, use `lookup_depth=6` and `extracted_types=^(?:executable|code|document)/`, and retain `submit_to_joesandbox=false` and `upload_extracted=false`. Keep AL result caching enabled. A narrow type filter preserves executable, script and document lookups at every permitted extraction depth; it excludes extracted images, generic text, URI files and archive containers. The submitted file is still looked up regardless of type. Coverage lost by this filter is explicit: a known extracted archive or a payload classified only as generic text will not be queried. An analyst can override `extracted_types=.*` when that coverage matters.

The largest guaranteed per-hash improvement is **known-finished: 4–8 requests → 2** when search returns its documented metadata. No batch endpoint is verified. A cold, genuinely unknown hash still needs one search.

## Evidence and boundaries

**Verified from supplied live evidence:** fleet submissions have `deep_scan=true`, JoeSandboxV2 selected, `lookup_depth=6`, `extracted_types=.*`; a recent submission generated 501 Joe tasks; Joe returns `You have exceeded the number of available API requests today`; upload flags are off. These observations were not reproduced.

**Verified from source:** the manifest accepts almost every type, enables caching, and defaults both upload flags to false. Scope checking is before client creation. The current service does not inspect `deep_scan`; it looks up every in-scope hash. `newest_first()` discards search metadata and sorts unique web IDs numerically. `_lookup()` checks up to five analyses with `analysis_info()`, and `execute()` fetches the selected analysis's info a second time before downloading `irjsonfixed`. Only `info.time` is used in result construction. [S1–S3]

The exact deployed framework package versions and AL retry-attempt limit were not available. Default Python has no installed jbxapi/AL packages; the pinned jbxapi 3.25.0 PyPI sdist was inspected instead. Accessible official core dispatcher source ends at `timeout_backstop`, so it does not establish a task retry bound. Counts below use **A = actual AL execution attempts for a hash**, not an assumed three attempts. Joe's current Basic guide returned HTTP 403; its Pro guide redirected to login. Endpoint response claims use the local saved official guide plus the current official client. Search metadata fields are documented, but their presence in this account's current replies remains to be checked after quota recovery. [S4–S7]

## Current request counts

Counts are external endpoint invocations per cold, in-scope service execution, with uploads disabled. An AL cache hit or out-of-scope task makes **zero** Joe requests. Let `k` be the number of status checks before finding a finished analysis, `1 ≤ k ≤ 5`.

| Hash outcome | Current logical requests | What happens |
|---|---:|---|
| Unknown, search returns `[]` | 1 | Search only; successful empty result. |
| Known and finished | `1 + k + 1 + 1 = k + 3`, **4–8** | Search, k info calls, duplicate selected info, report download. |
| Running, no finished analysis in the first five | **2–6** | Search and 1–5 info calls, then `RecoverableError`. |
| Search hits exist, but none of the first five is finished or recognized as running | **2–6** | Empty result despite a nonempty search; not a genuine negative lookup. |
| Daily request quota already exhausted at search | **1 per attempt**, **A total** | Joe API error becomes `RecoverableError`; each AL execution repeats search. |
| Quota reached later during lookup/report retrieval | **1–8 per attempt** | Work stops at the failing call; AL execution starts the entire lookup again. |

jbxapi's `_post()` starts its counter at 1 and stops at `i >= retries`; `retries=3` therefore permits **three total HTTP attempts**, not four. It retries timeouts, not returned API errors. Logical unknown calls can become 1–3 HTTP attempts; successful known-finished calls 4–24; running calls 2–18. A returned quota error by itself gets **no SDK retry**, but AL repeats it because the service labels it recoverable. Repeated report failures also repeat search and status work: with the newest analysis finished, A failing executions can spend roughly `4A` endpoint invocations. A timeout might already have been processed by Joe, so HTTP retries can consume allowance without a delivered response. Whether such attempts are charged is unverified. [S1, S4]

For 501 cold tasks, all truly unknown hashes need **501** logical calls; all known-finished hashes need **2,004–4,008** before retries. **501 tasks is not evidence of 501 distinct hashes, 501 misses, or 501 billable Joe requests.** The extraction fan-out, cache-hit proportion and retry count were not supplied.

## Supported Joe API opportunities

| Question | Verified answer | Consequence |
|---|---|---|
| Can search remove info calls? | Saved official `/v2/analysis/search` response includes `webid`, `status`, `time`, `detection`, `score`, hashes and runs. jbxapi returns the response objects unchanged. [S4–S6] | Retain objects instead of reducing them to IDs. Search metadata can supply status and the only info field currently used, `time`. |
| Is hash batching supported? | The guide documents one `q` string or scalar exact-match `sha256`/`sha1`/`md5` filters. Multiple different filters are ANDed. No documented hash-array, OR-hash syntax or batch-search method was found in the guide or client. [S4–S6] | Do not invent an endpoint or send joined hashes. Pagination lists analyses, not a batch reputation lookup. |
| Is report retrieval conditional? | `/v2/analysis/download` is a POST with `webid`, resource type and optional run. `irjsonfixed` is documented. No conditional-download/ETag/304 contract is documented or exposed by jbxapi. [S4–S6] | A locally cached report can avoid a download. A summary-only result avoids one call but loses signatures, contacts and dropped-file evidence. |
| Is account quota status available? | Cloud `/v2/account/info`, exposed as `account_info()`, documents daily/monthly current, limit and remaining quota. [S4–S6] | It exists, but the documented object does not identify separate API-request counters or a reset timestamp. Do not equate these quota fields with today's exhausted request allowance. |
| What resets the daily request limit? | The supplied error establishes a daily request limit. Reviewed primary sources do not establish its value, timezone, reset instant, endpoint exemptions or per-endpoint accounting. Search date filters use CET/CEST, which is not evidence of a quota reset timezone. [S5–S6] | Use a bounded cooldown/probe policy, not an asserted midnight reset. Confirm account-specific request accounting with Joe before adding budget calculations. |

These counts measure calls, not contractual quota units. Checking `account_info()` before every hash adds **one** call: unknown 1→2, optimized known 2→3, without proven request-budget information. Any account check should be operator-triggered or infrequent and outside the per-file path.

## Prioritized changes and quantified savings

### 1. Stop daily-quota retry amplification

Handle the observed daily-request-quota `ApiError` at **search, fallback info and report download**, not just upload. Match the specific message; the documented generic permission code 7 also covers unrelated permission failures, so code 7 alone is insufficient. Return an unscored `Joe Sandbox lookup unavailable` section marked `request.partial()`; do not raise `RecoverableError`, return a successful empty negative, or claim the hash is unknown. Invalid keys remain nonrecoverable errors; connection failures and genuine temporary outages remain recoverable. [S1, S4–S6, S8]

Add an account/API-URL-scoped circuit breaker: **3,600-second cooldown**, then at most one half-open search probe when a real task arrives. A successful probe closes the breaker; another daily-quota response reopens it. Do not run a timer that calls Joe without work. Use an operator-clear path for confirmed quota reset or account changes. Reset timing is unknown; this policy can delay restored coverage by up to one hour.

Savings for N tasks within one cooldown: current exhausted-at-search **N×A → at most W** initial quota responses with W active independent workers, then zero new calls per worker; an optional shared breaker reduces this to **one probe plus already-in-flight requests**. For the 501-task example, one worker goes **501×A → 1**, saving at least 500 calls if every task would otherwise execute once. A local breaker cannot guarantee a fleet-wide single probe. In a continuous exhausted workload, half-open probes are bounded to about one per hour per independent breaker.

### 2. Reuse analysis metadata and remove duplicate info

First carry the selected `analysis_info()` object in `Lookup` and reuse it: known-finished **4–8 → 3–7**, exactly one call saved, with no report-content loss.

Then preserve and sort search objects with the existing newest-web-ID ordering and five-analysis selection bound. Use a row's documented `status` and `time`; call `analysis_info()` only for rows missing required metadata. Do not treat missing/unknown status as finished. The common complete-metadata path becomes **unknown 1→1; known-finished 4–8→2; running 2–6→1**. This saves **50–75%** for known-finished hashes. For 501 all-known cold tasks: **2,004–4,008 → 1,002**. A complete fallback can retain the **3–7** bound from the first change. Continue downloading `irjsonfixed` for finished analyses to preserve current rich output.

If there is only a running analysis in lookup-only fleet mode, prefer an unscored pending section marked partial instead of immediate task retries: **2–6 calls per attempt / up to A×(2–6) → 1** with complete search metadata. This preserves the pending analysis link but does **not** fetch a report that finishes later in the same submission. The next submission can look it up again. Keep opt-in upload waiting behavior separate; never upload because a lookup is pending. If same-submission eventual completion is required, retain retries and quantify them as **A** searches instead of promising the one-call outcome.

### 3. Narrow fleet lookup types without flattening extraction depth

Set the fleet profile's Joe parameters to:

```yaml
JoeSandboxV2:
  lookup_depth: 6
  extracted_types: '^(?:executable|code|document)/'
  submit_to_joesandbox: false
  upload_extracted: false
```

Apply through the submitting account's actual submission profile/service overrides, not an unrelated user's settings. Effective submission `service_spec` overrides manifest defaults. Merely changing manifest defaults may leave existing profile values untouched. `deep_scan` is independent of these parameters and must not imply wider Joe scope. Selected services/categories and manifest accepts/rejects determine scheduling; the current scope check skips Joe calls only after a task reaches the service. [S2–S3, S7–S10]

If M of 500 extracted cold unknown tasks pass this filter, calls become **501 → 1+M**, saving **500−M**. M is unmeasured; no percentage reduction is claimed. For excluded known hashes, each skipped lookup saves the current **4–8** or optimized **2** calls. Remaining executable/script/document hashes retain depth-six coverage. A temporary `lookup_depth=0` reduces a single-root 501-file cold submission to **one root lookup**, but drops all extracted-file Joe coverage; use only as an explicit quota-containment choice. `lookup_depth=1` can miss payloads inside nested archives and is not the recommended steady-state default.

## Cache and deduplication choices

| Approach | Call savings and correctness | Recommendation |
|---|---|---|
| AL-native result/empty-result cache | Exact cache hit: unknown **1→0**, known **4–8→0** (optimized **2→0**), shared across workers. Key includes file hash, service/tool version, service parameters, `deep_scan`, max-files and other scan settings. `ignore_cache` bypasses it; `deep_scan=true` alone does not. Partial results use a random cache salt. Empty results have a configurable lifetime, default **five days** in reviewed source; a negative can hide a newly published Joe report until expiry. [S7–S9] | Keep `disable_cache=false`, and keep `ignore_cache=false` in routine fleet profiles unless explicitly required. Do not disable deep scan merely to seek cache hits. Accept the negative-staleness window consciously; positive AL results can also preserve an older report. |
| Service-local negative cache | For n repeats of one genuinely absent hash on the same worker, **n searches→1** during TTL; no benefit for a first burst of unique hashes. Lost on restart; independent replicas repeat misses. A six-hour TTL bounds new-report discovery delay only if AL does not already serve a five-day cached empty. | Not first-line: redundant with working AL caching. If shorter negative freshness is required, use partial empty negatives plus a bounded **10,000-entry, six-hour** cache, and respect explicit fresh lookup intent. Cache only a successful `search=[]`, never quota, timeout, denied report, pending analysis or “no finished match”. This requires a deliberate exception to the standard's no-cross-task-state rule. [S8] |
| Redis/shared lookup cache | n duplicate misses across workers **n→1** with TTL and single-flight; optional positive report cache: search+download **2→0** while valid, or **2→1** when rechecking search against a cached selected report. Report selection and report bodies require separate TTLs; new analyses, report mutation/deletion and account visibility can change results. | Defer until repetition or multiworker quota pressure justifies it. Provide an explicit service dependency; this unprivileged service must not receive unrestricted AL core Redis access. Namespace by API URL, account fingerprint, schema version and hash; apply bounded storage, TTLs and an expiring lock. Never put the raw API key in keys/logs. Cache failure must not generate unconstrained Joe fan-out. A dedicated shared quota breaker is smaller than a general report cache. |
| Per-submission deduplication | AL running-task keys contain SID, service and SHA; duplicate concurrent tasks cannot both acquire that key. This does not prove deduplication of every sequential retry or cross-submission lookup. [S7] | Do not add a “seen SHA” set: it can suppress a failed first attempt without returning its result. A correctly keyed completed-outcome cache/single-flight helps only real duplicates, not 501 different extracted hashes. No guaranteed savings beyond already documented AL protection. |

## Empty results and UI visibility

An unknown hash returns `Result()` with no sections. Existing tests explicitly expect that; the service standard forbids adding a “nothing found” section. AL stores a completed empty result as an `.e` key in `emptyresult`, reconstructs an empty body on cache hits, and excludes `.e` keys from summary/tree result processing. There is no Joe finding to render; absence of a Joe result card does not mean the service was unselected or made no request. Scope-skipped tasks likewise contain no findings, but are partial and cannot poison future wider lookups. Quota and pending states should have real unscored partial sections because they describe unavailable coverage, not a negative lookup. [S1, S7–S9]

## Rejected optimizations

- Uploading samples, using `submit_sample_url`, or enabling submission `report-cache`: starts the submission path, exposes data and consumes submission quota. None is a hash-lookup optimization.
- Concatenating hashes into `q`, imaginary batch/quota-reset endpoints, or conditional GETs against the documented POST download route: unsupported by reviewed primary sources.
- Polling `account_info()`/server status per file, trying another analysis after the account is exhausted, or treating all permission errors as a negative result: adds requests or conceals missing coverage.
- Skipping every clean report download by default: saves one optimized call (**2→1**) but removes network/signature/dropped-file context and changes current output. Summary-only mode would need explicit product approval.
- A local/shared negative cache as the cure for 501 unique first-time hashes: first searches remain **501**; scope reduction and quota containment address that workload.

## Implementation acceptance checklist

- [ ] Both upload flags remain false by default; all optimization/failure paths make zero submission/upload calls.
- [ ] Fake-client call assertions cover unknown=1, complete-metadata finished=2, complete-metadata running=1 with the selected pending policy, selected-info reuse=3, and five-row fallback ≤7.
- [ ] Preserve current newest-ID ordering, five-analysis limit, rich report parsing, timestamp/ontology fields and existing heuristics; incomplete search metadata triggers bounded info fallback.
- [ ] Daily-request-quota errors at search, info and download produce unscored partial coverage notices, no recoverable task retry, no negative cache entry, and a correctly scoped breaker.
- [ ] Breaker cooldown, half-open concurrency, key/account changes and worker restart behavior are explicit; any shared implementation tests lock expiry and already-in-flight requests.
- [ ] Running/accepted/submitted records and nonempty searches without finished analyses are never stored as a genuine absent-hash negative.
- [ ] Type/depth tests cover roots, nested executable/script/document payloads, excluded artifacts, invalid regex, analyst overrides and unchanged uploads-off behavior.
- [ ] Verify effective submitting-profile `service_spec`, `ignore_cache`, deep scan and cache-hit behavior using sanitized evidence after deployment authorization; do not infer them from another user's settings.
- [ ] Verify current account search fields and obtain Joe's actual request-limit/reset/accounting contract after quota recovery. Any newly observed field/endpoint must gain primary-source evidence before use.
- [ ] Update affected service docs and canonical external-lookup standard only when implementing approved behavior; run offline tests and the standard image gate in the implementation phase.

## Sources

- **S1:** `../../joesandboxv2/service.py`, especially lines 68–131 and 178–231; `../../tests/test_service.py`, lines 101–124 and 216–239. Paths here are relative to this research folder.
- **S2:** `../../joesandboxv2/analysis.py`, lines 15–41 and 74–77.
- **S3:** `../../service_manifest.yml`, lines 10–63; `../../requirements.txt` (jbxapi 3.25.0).
- **S4:** [Joe Security official jbxapi source](https://github.com/joesecurity/jbxapi/blob/master/jbxapi.py), [Python API reference](https://github.com/joesecurity/jbxapi/blob/master/docs/api.md), [pinned 3.25.0 PyPI metadata](https://pypi.org/pypi/jbxapi/3.25.0/json) and its linked sdist. The sdist's `jbxapi.py` lines 494–598, 608–616, 865–890 and error classes establish endpoint and retry behavior.
- **S5:** Saved official Basic API guide: `../../../joesandbox-service/joesandbox_api_docs/introduction.md`, search lines 346–433, download lines 277–320, account lines 537–562, error codes lines 569–583.
- **S6:** Original saved HTML: `../../../joesandbox-service/joesandbox_api_docs/docs/joesandbox-api-docs.html`, search response lines 1427–1443 and account lines 1876–1890; original [Basic guide URL](https://www.joesandbox.com/userguide?sphinxurl=api.html) (403 during research), [Pro guide URL](https://jbxcloud.joesecurity.org/userguide?sphinxurl=api.html) (login redirect).
- **S7:** Official AL core [tasking client](https://github.com/CybercentreCanada/assemblyline-core/blob/master/assemblyline_core/tasking_client.py), `get_task()`; [dispatch client](https://github.com/CybercentreCanada/assemblyline-core/blob/master/assemblyline_core/dispatching/client.py), `_request_work()` and `service_finished()`; [scheduler](https://github.com/CybercentreCanada/assemblyline-core/blob/master/assemblyline_core/dispatching/schedules.py), `build_schedule()`; [dispatcher reference](https://github.com/CybercentreCanada/assemblyline-core/blob/v4.7.4.stable11/assemblyline_core/dispatching/dispatcher.py). These are source references, not a verified deployed package snapshot.
- **S8:** `../../../al4-service-template/STANDARD.md`, Output rules and External lookup services; local official `../../../docs/assemblyline_docs_ASSEMBLYLINE_BOOK/assemblyline_docs_developer_manual/assemblyline_docs_services/assemblyline_docs_advanced/assemblyline_docs_partial_results.md`, lines 6–10 and 56–63.
- **S9:** Official AL base [cache key generation](https://github.com/CybercentreCanada/assemblyline-base/blob/master/assemblyline/common/caching.py), `generate_conf_key()`; [result model](https://github.com/CybercentreCanada/assemblyline-base/blob/master/assemblyline/odm/models/result.py), `help_build_key()`/`is_empty()`; [datastore helper](https://github.com/CybercentreCanada/assemblyline-base/blob/master/assemblyline/datastore/helper.py), `.e` filtering; [configuration model](https://github.com/CybercentreCanada/assemblyline-base/blob/master/assemblyline/odm/models/config.py), `DEFAULT_SUBMISSION.emptyresult_dtl=5`, extraction depth=6.
- **S10:** Local official `../../../docs/assemblyline_docs_ASSEMBLYLINE_BOOK/assemblyline_docs_odm/assemblyline_docs_models/assemblyline_docs_submission.md`, `SubmissionParams.service_spec`, `deep_scan` and `ignore_cache`; official framework [Task](https://github.com/CybercentreCanada/assemblyline-v4-service/blob/master/assemblyline_v4_service/common/task.py), `get_param()`/`partial()`/`save_error()`; [ServiceBase](https://github.com/CybercentreCanada/assemblyline-v4-service/blob/master/assemblyline_v4_service/common/base.py), `_handle_execute_failure()`.
