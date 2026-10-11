# Terminus

**Autonomous vulnerability intelligence and remediation agent.**
Terminus discovers newly published and updated CVEs, matches them against a software
inventory with ecosystem-aware version logic, researches each relevant finding with a
bounded, tool-using agent, ranks risk with an explainable deterministic engine, and
produces evidence-backed remediation recommendations. All of this is shown in a Streamlit
dashboard, a FastAPI backend and JSON/CSV reports.

> Terminus is a **research and recommendation** tool. It never installs patches, never
> runs commands on your systems, and every recommendation requires human review.

- Runs fully offline in **demo mode** on recorded API responses (no keys, no network).
- **Live mode** uses free public sources: NVD, CISA KEV, FIRST EPSS, OSV.dev and official vendor advisories.
- Optional extras: Tavily/Exa web search and an LLM research layer (LlamaIndex). Neither is needed for the
  deterministic core.

---

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/) (or plain `pip`).

```bash
git clone https://github.com/Asmit12357/terminus.git
cd terminus
uv sync                                    # creates .venv with runtime + dev tools
```

**Try it in under a minute (offline demo):**

```bash
uv run terminus import-inventory data/sample_inventory.json
uv run terminus scan --demo --mode full
uv run terminus findings
```

**Open the dashboard:**

```bash
uv run streamlit run app/dashboard.py
```

Then browse to <http://localhost:8501>. On a fresh database the Overview page offers a
one-click **Load sample inventory and run demo scan**.

Without uv: `python -m venv .venv`, activate it, run `pip install -e .`, then use
`python -m app.cli ...` in place of `uv run terminus ...`.

### Live scans

```bash
cp .env.example .env            # optional: add TERMINUS_NVD_API_KEY for faster NVD paging
uv run terminus scan --mode incremental   # CVEs modified since the last scan (default window: 7 days)
uv run terminus scan --mode full          # every inventory product + OSV package advisories
```

### API

```bash
# .env: TERMINUS_API_TOKEN=<long random string>
uv run terminus serve-api                 # http://127.0.0.1:8000/docs
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8000/api/findings?tier=P1"
```

### Export

```bash
uv run terminus export --format json --out terminus-findings.json
uv run terminus export --format csv  --out terminus-findings.csv --tier P1 P2
```

---

## Architecture

```
            +-------------------- data sources (read-only) --------------------+
            |  NVD CVE API 2.0 | CISA KEV | FIRST EPSS | OSV.dev | vendor pages |
            |                  (optional) Tavily / Exa web search              |
            +--------------------------------+---------------------------------+
                                             | HttpClient: https-only, timeouts, retries+backoff,
                                             | rate limits, size caps, SQLite cache, no redirects
inventory (JSON/CSV) --> validation --> SQLite <--+
                                         |        |
                       +-----------------v--------+-------------------------------+
                       | Scanner: ingest -> candidate matching -> KEV/EPSS enrich |
                       +-----------------+-----------------------------------------+
                                         | per CVE with inventory candidates
                       +-----------------v-----------------------------------------+
                       | Research agent (bounded)                                  |
                       |  ToolRegistry: 8 read-only tools, validated arguments,    |
                       |  tool/search/time budgets, audit trace                    |
                       |  Policy: deterministic next-step selection                |
                       |  Optional: LlamaIndex FunctionAgent over the same tools   |
                       +-----------------+-----------------------------------------+
                                         | deterministic: matcher, fix verification,
                                         | risk engine, recommendation builder
                       +-----------------v-----------------------------------------+
                       | Findings + scan history (SQLite)                          |
                       +------+--------------------+-----------------------+-------+
                              |                    |                       |
                       Streamlit dashboard   FastAPI (token)       JSON / CSV reports
```

| Path | Responsibility |
|---|---|
| `app/connectors/` | `http.py` hardened client; `nvd.py`, `kev.py`, `epss.py`, `osv.py`, `vendor.py` (allow-listed advisory pages), `search.py` (Tavily/Exa) |
| `app/matching/` | `normalize.py` (CPE/purl parsing, name normalization, curated aliases), `versions.py` (per-ecosystem comparators, ranges), `matcher.py` (status decision), `fixes.py` (fixed-version verification) |
| `app/risk/` | `scoring.py` explainable priority engine (`RiskConfig`) |
| `app/agent/` | `tools.py` (schemas, registry, budgets), `orchestrator.py` (policy, stopping), `llm.py` (LlamaIndex layer, system prompt), `state.py`, `context.py` |
| `app/storage/` | `db.py` schema/connections, `repository.py` (all SQL, parameterized) |
| `app/reports/` | `recommendation.py` (deterministic recommendations), `export.py` (JSON/CSV) |
| `app/` | `scanner.py` pipeline, `sources.py` (live/demo bundles), `service.py`, `cli.py`, `api.py`, `dashboard.py`, `ui.py`, `security.py` (untrusted-text handling), `benchmark.py` |
| `data/` | synthetic sample inventory; `fixtures/` recorded API responses for demo mode and tests |
| `scripts/record_fixtures.py` | re-records the demo fixtures from the live APIs |
| `tests/` | unit, integration, security and evaluation tests (no network) |

**Design rule:** matching, fixed-version verification, scoring and recommendations are
deterministic Python code, so they stay testable and reproducible. An LLM, if configured,
can only choose which research tools to call and write a clearly labelled analyst note.

---

## How it works

### 1. Inventory

One record per software installation on an asset. JSON may be nested
(`{"assets": [{..., "software": [...]}]}`) or flat (a list, or `{"items": [...]}`). CSV
uses one row per software item. See `data/sample_inventory.json` and `.csv`, which are
fully synthetic and use `*.corp.example` hostnames.

| Field | Required | Notes |
|---|---|---|
| `asset_id` | yes | `[A-Za-z0-9._:-]`, max 64 |
| `hostname` | no | DNS name |
| `os_name`, `os_version` | no | |
| `software_name` | yes | product or package name |
| `software_version` | no* | missing -> every finding for it is **unverified** |
| `ecosystem` | no | `pypi npm maven nuget go cargo rubygems deb rpm generic` (default `generic`) |
| `vendor` | no | strengthens identity matching |
| `cpe` | no | CPE 2.3 formatted string |
| `purl` | no | package URL, e.g. `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| `criticality` | no | `low medium high critical` (default `medium`) |
| `internet_exposed` | no | `true/false`; empty = unknown (flagged as missing) |
| `environment` | no | `production staging development test` |
| `business_context`, `owner` | no | free text |

Validation is row-level: unknown fields, bad CPEs or purls, invalid enums and hostnames
are reported with row and field, and nothing is imported until the file has no errors.
Limits are 5 MB and 20,000 items, with control and bidi characters stripped. The importer
only ever calls `json.loads` and `csv.DictReader`.

### 2. Vulnerability ingestion

- **NVD CVE API 2.0**: `lastMod*` date windows (split into 120-day chunks), pagination,
  product queries (`virtualMatchString`) in full scans, the API key sent in a header,
  6 s request pacing without a key (0.7 s with one), and NVD's 403 rate-limit response
  is retried.
- **CISA KEV**: the full catalog once per scan (cached for 12 h). If KEV is unreachable
  the last copy is used and marked stale; with no copy at all, KEV status is **unknown**,
  never "not listed".
- **FIRST EPSS**: batched queries for candidate CVEs only.
- **OSV.dev**: package advisories (GHSA, PyPA, ...) with ecosystem-native ranges.
- **Vendor advisories**: only URLs that NVD or OSV list as advisories, fetched only from
  an allow-listed domain over HTTPS, capped at 1.5 MB, following at most 3 redirects that
  stay on the allowlist.

CVE records are upserted by ID with a content hash: an updated record bumps its
revision and re-assesses findings in place, without duplicates. Each record stores the
source's `published`/`lastModified` times and Terminus's own `retrieved_at`. Malformed
entries are skipped and reported, never guessed.

### 3. Matching and statuses

Identity, strongest first: `cpe_exact`, `package_exact` (OSV ecosystem + name),
`curated_alias` (documented table in `normalize.py`), `vendor_product` (normalized
vendor and product both equal), `name_only` (no vendor given), and `ambiguous` (vendor
mismatch, or a token-contained name like `openssl-libs`). Normalization folds case,
Unicode and separators and strips legal suffixes from vendors only, so `log4j-core`
stays distinct from `log4j-api`.

Versions are compared with the ecosystem's own rules, never lexically:

| Scheme | Used for | Notes |
|---|---|---|
| PEP 440 | PyPI | via `packaging` |
| SemVer 2.0 | npm, Cargo, Go | pre-release precedence per spec; incomplete versions rejected |
| Maven | Maven | alpha < beta < milestone < rc < snapshot < release < sp |
| dpkg | Debian/Ubuntu | epoch, `~`, revision |
| rpm | RHEL/Fedora | `rpmvercmp`, `~` and `^` |
| generic | CPE/vendor versions | numeric segments, pre-release words, letter patch suffixes (`1.0.1g`, `9.2p1`); unknown words or wildcards raise an error and the result becomes **unverified** |

Range evaluation honours inclusive/exclusive start and end bounds, exact CPE versions,
CPE `update` fields (`2.0` + `beta9`), OSV `introduced: "0"`, `fixed` and `last_affected`
events, and OSV `versions` lists. OSV `GIT` ranges are ignored rather than guessed.

| Status | Rule |
|---|---|
| **Confirmed affected** | reliable identity; version inside an affected range; not contradicted by another reliable source; not distro-vs-upstream, not unbounded, not platform-conditional |
| **Potentially affected** | in range but name-only identity, sources disagree, distribution package (backports), unbounded NVD entry, or an unevaluable platform condition |
| **Unverified** | version missing or unparseable, identity ambiguous, NVD analysis incomplete, or only a description keyword match on a CVE awaiting NVD analysis |
| **Confirmed unaffected** | reliable identity and every reliable source puts the version outside the ranges (NVD analysed, or an ecosystem advisory is present) |

No match is **not** "safe". A CVE that never relates to an item produces no finding at
all. "Confirmed unaffected" requires a positive, sourced determination.

### 4. Fixed versions

Only structured sources propose fixed versions: NVD `versionEndExcluding` on the range
that contains the installed version, and OSV `fixed` events.

| Status | When |
|---|---|
| `verified` | OSV advisory, NVD + OSV agree, or NVD corroborated by an allow-listed vendor page that names the CVE and that exact version within 1,500 characters |
| `single_source` | NVD only; the recommendation asks to confirm with the vendor advisory |
| `conflict` | sources disagree; no fixed version is asserted, and the highest named version is shown as a conservative target |
| `unknown` | no structured source states a fix; the recommendation says to consult the vendor advisory |

Vendor page text, web search results and LLM output can **never introduce** a fixed
version. Pages that contain instruction-like text are excluded from corroboration.

### 5. Risk prioritization

```
score = (severity + known_exploitation + exploit_likelihood + exposure
         + asset_criticality + environment + actionability)
        x status_factor x (0.85 + 0.15 x identity_confidence)
```

| Factor | Weight | Scaling | Missing value |
|---|---|---|---|
| Severity (CVSS base) | 30 | score / 10 | ranked as 5.0, flagged |
| Known exploitation (CISA KEV) | 25 | listed = full | unknown = 20%, flagged |
| Exploit likelihood (EPSS) | 15 | sqrt(probability) | ranked as 0.05, flagged |
| Internet exposure | 10 | internet-facing = full | unknown = 50%, flagged |
| Asset criticality | 10 | critical 1.0 / high 0.7 / medium 0.4 / low 0.1 | - |
| Environment | 5 | production 1.0 / staging 0.4 / dev/test 0.2 | unknown = 60%, flagged |
| Actionability | 5 | fixed version known | - |

`status_factor`: confirmed affected 1.0, potentially affected 0.75, unverified 0.5,
confirmed unaffected 0. **Tiers:** P1 >= 70, P2 >= 50, P3 >= 30, otherwise P4;
unaffected is INFO. **Overrides:** confirmed affected + KEV is at least P2, or P1 if
internet-facing; unverified findings are capped at P2.

- CVSS (severity), KEV (observed exploitation) and EPSS (probability of future activity)
  are separate factors. A high EPSS score is never described as "exploited".
- Raw source values are stored separately (`cvss`, `kev`, `epss`, each with retrieval
  timestamps) from the derived `priority`. Each factor records its raw value, points,
  maximum and explanation.
- Ranking is deterministic: tier, then score, then CVSS, then stable tie-breakers.
- All weights, placeholders and thresholds are configurable through a JSON file named in
  `TERMINUS_RISK_CONFIG` (fields of `RiskConfig`).
- Limitations: the weights are expert judgment, not a calibrated model; EPSS is
  CVE-level and does not reflect your environment; asset criticality is only as good as
  the inventory.

### 6. Research agent

Eight read-only tools, each with a strict Pydantic input schema (`extra="forbid"`):
`get_cve_details`, `get_inventory_matches`, `search_official_vendor_advisories`,
`search_additional_research_sources`, `get_kev_status`, `get_epss_score`,
`verify_affected_and_fixed_versions` and `generate_remediation_recommendation`.

The deterministic policy picks the next step from the evidence gathered so far:

```
CVE details -> inventory matches -> (stop if none) -> KEV -> EPSS -> verify candidates
  -> advisory research, once per distinct package/product, only for candidates that are
     unsettled or lack a verified fix -> re-verify if new evidence arrived
  -> web search only if uncertainty remains and a provider is configured
  -> recommendations -> stop
```

- **Budgets** per CVE: maximum tool calls, search calls and wall-clock seconds
  (`TERMINUS_AGENT_*`).
- **Termination:** every step has a unique key that runs at most once, and the key set is
  finite.
- If a budget stops research, the remaining candidates are still finalized
  deterministically from the evidence already gathered, and each report lists the
  research step that was skipped.
- **Failures:** a failed tool call is recorded as failed (`ok: false` with an error) and
  is never reported as a completed verification.
- **LLM layer** (`TERMINUS_LLM_PROVIDER=openai|anthropic`, install the matching extra): a
  LlamaIndex `FunctionAgent` gets the same registry-backed tools, `max_iterations` and a
  timeout. Its output is stored only as `ai_interpretation`, labelled unverified.
  Afterwards the deterministic policy fills any gaps, so results never depend on the LLM.

### 7. Reports

Every finding contains:

- the CVE ID and summary;
- asset and installed version, with match status and confidence;
- CVSS score and vector;
- KEV and EPSS values, each with retrieval timestamps;
- priority score and tier with contributing factors;
- affected-version evidence (claim, source, trust tier, URL, retrieved time);
- fixed-version status and sources;
- the recommendation and its steps;
- official vendor advisory URLs and supporting URLs;
- missing information, unresolved uncertainty and the next verification step;
- the research trace and date of last assessment.

The JSON report separates `verified_facts` from `ai_interpretation`. Every export carries
`patch_applied: false` and a disclaimer.

---

## Testing

```bash
uv run pytest                 # 257 tests, no network, no API keys
uv run ruff check . && uv run ruff format --check .
uv run mypy                   # strict-ish type check of app/
uv run terminus benchmark     # matching benchmark against recorded NVD/OSV data
```

The suite covers:

- **Inventory:** valid and invalid files, oversize input, encoding, control characters,
  duplicates.
- **Matching:** version semantics for every scheme, range boundaries, identity rules,
  every status path, OSV/NVD disagreement, distro backports, platform conditions,
  keyword candidates.
- **Connectors:** retries, `Retry-After`, timeouts, 4xx vs 5xx, redirects, size limits,
  https-only, cache and stale fallback, rate limiting, pagination, 120-day chunking,
  malformed payloads.
- **Enrichment:** KEV and EPSS parsing and batching.
- **Risk:** scoring, missing data, determinism, configurability, and how exploitation
  evidence and asset context change priority.
- **Fixes and recommendations:** fixed-version verification, conflicts, the rule that
  vendor text can't introduce a fix, recommendations never claiming patching.
- **Agent:** budgets, termination, rejected tools and arguments, CVE scoping, failure
  reporting, and prompt injection in descriptions and search results. A scripted,
  "compromised" LLM is run through the real LlamaIndex `FunctionAgent`.
- **Storage:** persistence, updated CVEs without duplicates, scan history, SQL injection
  strings as data.
- **Exports and API:** JSON structure, CSV formula injection, token enforcement, input
  validation, the allow-list of mutating routes.
- **Static security checks:** no `eval`/`exec`/`subprocess`/`pickle`/`os.system` in
  `app/`, and no value-interpolated SQL.

**Benchmark** (35 cases: real CVEs with synthetic installed versions, expected outcomes
from vendor advisories):

| correct | false positives | false negatives | uncertain (all expected) |
|---|---|---|---|
| 35 | 0 | 0 | 5 |

The five uncertain cases are deliberate:

- a missing version;
- an unparseable vendor build string;
- a name-only identity;
- an RHEL `curl` package and an Ubuntu `openssh-server` package, where backports make
  the upstream version inconclusive.

---

## Configuration

All settings are environment variables with the `TERMINUS_` prefix, or a local `.env`
(git-ignored); see `.env.example`. Secrets use `SecretStr`, so they never appear in
`repr`, logs or responses.

| Variable | Default | Purpose |
|---|---|---|
| `TERMINUS_MODE` | `live` | `demo` serves recorded fixtures |
| `TERMINUS_DB_PATH` | `./terminus.db` | SQLite file |
| `TERMINUS_API_TOKEN` | - | required for every `/api` route (API refuses requests without it) |
| `TERMINUS_NVD_API_KEY` | - | optional; raises NVD rate limits |
| `TERMINUS_INCREMENTAL_WINDOW_DAYS` | `7` | first incremental window |
| `TERMINUS_SEARCH_PROVIDER` | `none` | `tavily` or `exa` (+ `TERMINUS_TAVILY_API_KEY` / `TERMINUS_EXA_API_KEY`) |
| `TERMINUS_LLM_PROVIDER` | `none` | `openai` or `anthropic` (+ key, `TERMINUS_LLM_MODEL`; `uv sync --extra agent-openai`) |
| `TERMINUS_AGENT_MAX_TOOL_CALLS` / `_SEARCH_CALLS` / `_SECONDS` | `12` / `2` / `60` | research budgets per CVE |
| `TERMINUS_FETCH_VENDOR_PAGES` | `true` | allow-listed vendor page retrieval |
| `TERMINUS_VENDOR_DOMAIN_ALLOWLIST` | built-in list | JSON array of domains |
| `TERMINUS_RISK_CONFIG` | - | JSON overrides for `RiskConfig` |

Which integrations need keys: NVD, KEV, EPSS, OSV and vendor pages need **none** (an NVD
key only speeds things up). Tavily, Exa, OpenAI and Anthropic need their own keys and are
optional.

---

## Security considerations

- **Untrusted content.** CVE descriptions, vendor pages and search results are
  normalized (NFKC), stripped of zero-width, bidi, control and ANSI characters, truncated,
  and scanned for prompt-injection patterns: instruction override, role reassignment,
  secret exfiltration, verdict tampering, tool invocation, command execution, fake
  delimiters and encoded blobs. Flags are recorded on the finding.
- **Separation of evidence and instructions.** Untrusted text sent to an LLM is wrapped
  in `<untrusted_document>` fences that the content cannot close. The system prompt
  declares it to be data. No retrieved text can choose tools, change a status, set a
  fixed version or alter priority, and those decisions are made in code.
- **Tools.** Read-only, allow-listed by name, schema-validated, scoped to the CVE under
  investigation, budgeted and audited. Nothing executes commands, scripts, repository
  code or exploit payloads, and a static test enforces that.
- **Network.** HTTPS only, timeouts, retry caps, response-size caps, no automatic
  redirects, and vendor fetches limited to an allowlist.
- **Storage.** Parameterized SQLite queries only. `LIKE` wildcards are escaped. The repo
  never deserializes with pickle or YAML.
- **Logging.** Only host and path are logged, never headers, query strings, keys or
  inventory contents.
- **API.** Bound to localhost by default. A bearer token with constant-time comparison is
  required for every `/api` route, and the API refuses requests when no token is
  configured. Only two mutating routes exist (import inventory, start scan). Responses
  carry strict security headers, there is no CORS, and errors are generic.
- **Dashboard.** Bound to `127.0.0.1`, XSRF protection on, 5 MB upload cap. Untrusted
  text is rendered as plain text, never Markdown or HTML. Links are shown only for
  validated `http(s)` URLs. Operations are limited to import, scan, view and export.
- **Exports.** CSV cells are protected against spreadsheet formula injection.
- **Data.** Only synthetic sample data ships with the repository. Real inventories and
  `.env` are git-ignored.

Do not expose the dashboard or API on a network without adding authentication and TLS
in front of them.

---

## Data sources and attribution

- **NVD**: National Vulnerability Database, CVE API 2.0. *This product uses the NVD API
  but is not endorsed or certified by the NVD.*
- **CISA Known Exploited Vulnerabilities Catalog**: cisa.gov/known-exploited-vulnerabilities-catalog
- **FIRST EPSS**: Exploit Prediction Scoring System, api.first.org (Jacobs et al., FIRST.org).
- **OSV.dev**: open-source vulnerability database, including GitHub Security Advisories
  and PyPA.
- **Vendor advisories**: the respective vendors (Apache, OpenSSL, curl, nginx, ...). The
  demo fixtures store only short excerpts around CVE mentions.

`data/fixtures/` contains API responses recorded on the date in `manifest.json` with
`scripts/record_fixtures.py`. They are used for demo mode and tests. Values (EPSS
especially) drift over time; live scans always fetch fresh data.

---

## Limitations

- Distribution packages are compared with upstream ranges, so backported fixes show as
  *potentially affected* until checked against the distribution's security tracker.
  Distro-specific OSV ecosystems (e.g. `Debian:12`) are a natural next step.
- CVEs awaiting NVD analysis have no CPE data; they surface only as keyword candidates
  (unverified).
- The curated alias table covers common packages only. Unknown products rely on
  CPEs/purls or exact vendor and product names.
- The fixed version from NVD for exact-version CPE listings (e.g. Apache httpd 2.4.49) is
  unknown by design. The recommendation then points to the vendor advisory.
- Vendor page corroboration is a proximity heuristic over allow-listed pages, not a
  parser of every vendor's format.
- No scheduler yet. Run `terminus scan --mode incremental` from cron or Task Scheduler.
- The LLM layer has been exercised with a scripted mock LLM in tests, not with a live
  provider in this repository's CI.

## License

MIT, see [LICENSE](LICENSE).
