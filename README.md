# Terminus

**Command-line vulnerability intelligence and remediation agent.**
Terminus discovers newly published and updated CVEs, matches them against your software
inventory with ecosystem-aware version logic, researches each relevant finding with a
bounded, tool-using agent, ranks risk with an explainable deterministic engine, and tells
you what to upgrade and why, with evidence and source links.

> Terminus is a **research and recommendation** tool. It never installs patches, never
> runs commands on your systems, and every recommendation requires human review.

- One `terminus` command. No web server, browser or dashboard is needed.
- **Demo mode** runs offline on recorded API responses that ship with Terminus. It needs
  no keys, and no network after installation.
- **Live mode** uses free public sources: NVD, CISA KEV, FIRST EPSS, OSV.dev and official
  vendor advisories. No paid API is needed.
- Optional add-ons: Tavily/Exa web search, an LLM research layer (LlamaIndex), a local web
  dashboard and a REST API. The core workflow needs none of them.

---

## Install

### Prerequisites

| Requirement | Notes |
|---|---|
| Operating system | Windows 10/11 or Linux (verified on Windows 11 and Ubuntu 24.04 under WSL2). macOS should work but has not been tested. |
| [uv](https://docs.astral.sh/uv/) | Installs Terminus in its own isolated environment and downloads Python 3.12+ automatically if you do not have it. |
| [Git](https://git-scm.com/) | uv uses it to fetch Terminus from GitHub. |
| Network | Installing needs github.com and pypi.org. Live scans need services.nvd.nist.gov, www.cisa.gov, api.first.org and api.osv.dev. Demo scans need no network. |

Install uv and Git if you do not have them:

```powershell
# Windows (PowerShell)
winget install --id astral-sh.uv -e
winget install --id Git.Git -e
```

```bash
# Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
sudo apt install git        # or your distribution's package manager
```

Open a **new** terminal afterwards so both commands are on your `PATH`.

### Install Terminus

```bash
uv tool install git+https://github.com/Asmit12357/terminus.git
```

Check that it works. This runs from any folder:

```bash
terminus --help
terminus info
```

If your shell says `terminus` is not found, run `uv tool update-shell` and open a new
terminal.

---

## Use

### 1. Try it with the demo data (offline)

```bash
terminus init                        # creates your data folder and a config template
terminus import-inventory --sample   # a synthetic inventory: 16 programs on 6 servers
terminus scan --demo                 # recorded vulnerability data bundled with Terminus
terminus findings                    # ranked list; every row starts with an ID
terminus queue                       # one upgrade target per installed program
terminus show 6e32c516               # full evidence for one finding (an ID from `findings`)
```

> **Demo vs live.** `scan --demo` uses API responses recorded on 2026-10-11, and every
> demo result is labelled `DEMO DATA`. The real values change over time (EPSS
> especially), so do not act on demo results. A normal `terminus scan` always queries the
> live sources and never falls back to demo data. If a source is unreachable, the scan
> reports it as unavailable.
>
> Demo and live data are never mixed in one database. Your first live scan removes the
> demo results and recorded records, keeping your inventory and scan history. A demo
> scan is refused on a database that already holds live results. To try the demo there
> anyway, give it its own folder, for example
> `terminus --home terminus-demo import-inventory --sample`.

### 2. Scan your own software

Start from the sample as a template, then edit, validate and import it:

```bash
terminus sample-inventory --format csv --out my_inventory.csv
terminus validate my_inventory.csv
terminus import-inventory my_inventory.csv
```

The format is described under [Inventory](#1-inventory). An import with errors is
rejected as a whole, and the previous inventory is kept.

### 3. Live scans

```bash
terminus scan --mode full     # every inventory product + OSV package advisories
terminus scan                 # incremental: CVEs changed since the last scan (first run: 7 days)
```

Without an NVD API key, NVD allows about 5 requests per 30 seconds, so Terminus spaces
out its requests. That pacing dominates scan time. In testing (October 2026, no keys), a
full scan of the sample inventory took about 4½ minutes and an incremental scan about
4 minutes. A free key ([request one here](https://nvd.nist.gov/developers/request-an-api-key))
cuts the spacing from 6 seconds to 0.7 seconds per request. Within a scan, each vendor
advisory page is downloaded once, however many CVEs cite it, and a host that is
unreachable is not retried for every CVE.

Two budgets keep scans bounded. Both are reported as notes in the scan output, never
applied silently:

- `TERMINUS_NVD_MAX_PAGES` (default 20 pages of 500, so 10,000 records): NVD currently
  modifies more than 10,000 records a week. When a window holds more changes than this
  budget, Terminus does not page through a truncated list. It fetches every newly
  published CVE plus every change to the inventory's own products. Nothing that matches
  the inventory by CPE is skipped.
- `TERMINUS_AGENT_MAX_FINDINGS_PER_SCAN` (default 200): the number of candidate CVEs
  researched per scan. Candidates are triaged first: KEV-listed CVEs, then CVEs never
  researched before, then by match status, CVSS and recency. A large backlog (a first
  full scan can find over 1,000 old candidate CVEs) is worked through over the next
  scans, and earlier findings stay in place meanwhile. Raise the budget in `config.env`
  to finish sooner.

### 4. Review and export

```bash
terminus findings --tier P1 P2
terminus findings --asset app-prod-02 --product log4j
terminus scans                                      # scan history
terminus export --format csv  --out findings.csv --tier P1 P2
terminus export --format json --out findings.json
```

`init`, `info`, `validate`, `import-inventory`, `scan`, `findings`, `show`, `queue`,
`scans` and `benchmark` accept `--json` for scripting. Progress and warnings go to
stderr, results to stdout.

### Command reference

| Command | Purpose |
|---|---|
| `terminus init [--from-db FILE]` | Create the data folder, the `config.env` template and the database; optionally import an existing database |
| `terminus info` | Show data locations, configured keys (names only) and optional components |
| `terminus validate FILE` | Check an inventory (JSON/CSV) without importing it |
| `terminus import-inventory FILE` / `--sample` | Validate and import an inventory, replacing the active one |
| `terminus sample-inventory [--format csv] [--out FILE]` | Write the synthetic sample (refuses to overwrite a file without `--force`) |
| `terminus scan [--mode incremental\|full] [--demo]` | Run a scan |
| `terminus findings [filters] [--limit N]` | Ranked findings (`--tier`, `--status`, `--asset`, `--cve`, `--product`) |
| `terminus show ID` | Evidence, priority factors and recommendation for one finding |
| `terminus queue` | Consolidated upgrade plan: one target version per installed program |
| `terminus scans` | Scan history |
| `terminus export [filters] [--format json\|csv] [--out FILE]` | Report export |
| `terminus benchmark` | Matching benchmark against recorded NVD/OSV data |
| `terminus dashboard` / `terminus serve-api` | Optional web dashboard / REST API (see below) |

Global options go before or after the command: `--home DIR` (data folder), `--db FILE`
(database file) and `-v` (debug logging).

**Exit codes:**

- `0`: success.
- `1`: the command ran, but the result is negative (invalid inventory rows, failed scan,
  unknown finding ID, benchmark mismatch).
- `2`: usage or input-file error.
- `3`: environment or configuration problem (data folder not writable, unusable
  database, or a provider configured without its key or package).
- `130`: interrupted.

---

## Where Terminus keeps your data

Everything Terminus writes goes into one per-user folder, the *Terminus home*. It is
never the installation folder or the folder you run commands from.

| System | Terminus home |
|---|---|
| Windows | `%LOCALAPPDATA%\Terminus` (for example `C:\Users\you\AppData\Local\Terminus`) |
| Linux | `$XDG_DATA_HOME/terminus`, by default `~/.local/share/terminus` |
| macOS | `~/Library/Application Support/Terminus` |

It contains `terminus.db` (inventory, findings, scan history and cached API responses)
and `config.env` (your settings). `terminus info` prints the exact paths. To use a
different folder, set `TERMINUS_HOME` or pass `--home DIR`. To use a different database,
set `TERMINUS_DB_PATH` or pass `--db FILE`.

Reinstalling or upgrading Terminus never touches this folder. When a new release changes
the database schema, Terminus first copies the old file to `terminus.db.v<N>.bak`. It
refuses to open a database written by a newer release, or a SQLite file that is not a
Terminus database, rather than modify it.

## Configuration and optional API keys

Demo scans and live scans of the free public sources need no configuration. For the
extras, run `terminus init`, then edit `config.env` in your Terminus home:

```powershell
notepad "$env:LOCALAPPDATA\Terminus\config.env"     # Windows
```

```bash
nano ~/.local/share/terminus/config.env              # Linux
```

| Setting | Effect |
|---|---|
| `TERMINUS_NVD_API_KEY` | Faster live NVD scans (the key is free) |
| `TERMINUS_SEARCH_PROVIDER=tavily` + `TERMINUS_TAVILY_API_KEY` (or `exa` + `TERMINUS_EXA_API_KEY`) | Supplementary web search during live research |
| `TERMINUS_LLM_PROVIDER=openai` + `TERMINUS_OPENAI_API_KEY` (or `anthropic` + `TERMINUS_ANTHROPIC_API_KEY`) | LLM-written analyst notes, labelled as unverified. Needs the matching extra (see below). |

Environment variables with the same names override `config.env`. A `.env` file in the
current folder is **not** read, so running Terminus inside an untrusted checkout cannot
redirect its data sources or database. `terminus info` shows which keys are set (names
only, never values) and what each optional component needs. If a provider is configured
but its key or package is missing, `terminus scan` stops with exit code 3 and says how to
fix it. It never silently runs without the provider.

### Optional components

Optional components are installed as extras. Reinstalling with an extra replaces the
tool's environment but leaves your data alone:

```bash
# LLM research layer (pick your provider)
uv tool install --force "terminus[agent-openai] @ git+https://github.com/Asmit12357/terminus.git"
uv tool install --force "terminus[agent-anthropic] @ git+https://github.com/Asmit12357/terminus.git"

# Local web dashboard and/or REST API
uv tool install --force "terminus[dashboard,api] @ git+https://github.com/Asmit12357/terminus.git"
terminus dashboard            # http://127.0.0.1:8501, local only
terminus serve-api            # http://127.0.0.1:8000/docs; needs TERMINUS_API_TOKEN
```

The dashboard and API are thin views over the same data as the CLI. If their extras are
not installed, `terminus dashboard` and `terminus serve-api` exit with code 3 and print
the install command. The core install has 15 packages. The dashboard and LLM extras add
about 80 more, and installing them can take several minutes.

## Update or uninstall

```bash
uv tool upgrade terminus       # fetch the latest version from GitHub
uv tool uninstall terminus     # remove the program (your data stays)
```

To delete your data as well, remove the Terminus home folder that `terminus info` shows.

### Upgrading from 0.1

Version 0.1 kept `terminus.db` and `.env` inside the cloned repository folder. To keep
that history, import the old database into your Terminus home. Run this from the old
clone folder:

```bash
terminus init --from-db terminus.db
```

The old file is opened read-only and left unchanged. The import refuses to overwrite a
Terminus home that already holds an inventory, scans or findings. When you run
`uv run terminus info` inside an old clone, it points out the 0.1 database for you. Move
any settings from the old `.env` into `config.env`.

Other changes in 0.2:

- The Python package is now `terminus` (it was `app`), so it cannot collide with other
  projects' `app` packages.

- The sample inventory and demo fixtures moved from `data/` to `terminus/data/`, so they ship
  with the installed package. Use `terminus import-inventory --sample` or
  `terminus sample-inventory`.
- `.env.example` is now the `config.env` template that `terminus init` installs.
- Streamlit, pandas, FastAPI and uvicorn are optional extras rather than core
  dependencies.
- Scan progress is printed to stderr.

## Development

```bash
git clone https://github.com/Asmit12357/terminus.git
cd terminus
uv sync                       # .venv with the runtime, optional components and dev tools
uv run terminus --help        # runs your working copy
uv run pytest                 # full suite: no network, no API keys
```

In a source checkout you can also run the dashboard directly with
`uv run streamlit run terminus/dashboard.py`.

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
                         terminus CLI     (optional) dashboard / API   JSON / CSV reports
```

| Path | Responsibility |
|---|---|
| `terminus/connectors/` | `http.py` hardened client; `nvd.py`, `kev.py`, `epss.py`, `osv.py`, `vendor.py` (allow-listed advisory pages), `search.py` (Tavily/Exa) |
| `terminus/matching/` | `normalize.py` (CPE/purl parsing, name normalization, curated aliases), `versions.py` (per-ecosystem comparators, ranges), `matcher.py` (status decision), `fixes.py` (fixed-version verification) |
| `terminus/risk/` | `scoring.py` explainable priority engine (`RiskConfig`) |
| `terminus/agent/` | `tools.py` (schemas, registry, budgets), `orchestrator.py` (policy, stopping), `llm.py` (LlamaIndex layer, system prompt), `state.py`, `context.py` |
| `terminus/storage/` | `db.py` schema/connections, `repository.py` (all SQL, parameterized) |
| `terminus/reports/` | `recommendation.py` (deterministic recommendations), `queue.py` (consolidated upgrade plan), `export.py` (JSON/CSV) |
| `terminus/` | `cli.py` (the `terminus` command), `scanner.py` pipeline, `sources.py` (live/demo bundles), `service.py`, `config.py` + `paths.py` (settings, data locations), `diagnostics.py` (optional-component checks), `security.py` (untrusted-text handling), `benchmark.py`; optional `api.py`, `dashboard.py`, `ui.py` |
| `terminus/data/` | bundled, read-only: synthetic sample inventory, `config.env` template, `fixtures/` recorded API responses for demo mode and tests |
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
uses one row per software item. `terminus sample-inventory [--format csv]` prints the
bundled sample (`terminus/data/sample_inventory.json` / `.csv`), which is fully synthetic and
uses `*.corp.example` hostnames.

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
uv run pytest                 # 302 tests, no network, no API keys
uv run ruff check . && uv run ruff format --check .
uv run mypy                   # strict-ish type check of terminus/
uv run terminus benchmark     # matching benchmark against recorded NVD/OSV data
```

An opt-in test builds the wheel, installs it with `uv tool install` into a temporary
folder and runs the demo workflow with the installed command (needs network access to
PyPI):

```bash
TERMINUS_INSTALL_TESTS=1 uv run pytest -m install                    # Linux/macOS
```

```powershell
$env:TERMINUS_INSTALL_TESTS = "1"; uv run pytest -m install          # Windows
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
  `terminus/`, and no value-interpolated SQL.
- **CLI:** the installed console script run from outside the repository, persistence
  across processes, the per-user data folder and its overrides, `config.env` versus a
  hostile `.env` in the working folder, missing keys and packages, optional extras that
  are not installed, exit codes, schema-upgrade backups, refusal of newer, foreign or
  corrupt databases, demo and live data never mixing, and the whole core workflow run
  with Streamlit, FastAPI, uvicorn, pandas and LlamaIndex made unimportable and listening
  sockets disabled.

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

## Configuration reference

All settings are environment variables with the `TERMINUS_` prefix, or lines in
`config.env` in the Terminus home (template: `terminus/data/config.env.example`). Environment
variables win. Secrets use `SecretStr`, so they never appear in `repr`, logs or
responses.

| Variable | Default | Purpose |
|---|---|---|
| `TERMINUS_HOME` | per-user data folder | where the database and `config.env` live (environment variable or `--home` only) |
| `TERMINUS_MODE` | `live` | `demo` makes every scan use the recorded fixtures |
| `TERMINUS_DB_PATH` | `<home>/terminus.db` | SQLite file; relative paths are resolved against the home |
| `TERMINUS_API_TOKEN` | - | optional REST API: required for every `/api` route (the API refuses requests without it) |
| `TERMINUS_NVD_API_KEY` | - | optional; raises NVD rate limits |
| `TERMINUS_INCREMENTAL_WINDOW_DAYS` | `7` | first incremental window |
| `TERMINUS_SEARCH_PROVIDER` | `none` | `tavily` or `exa` (+ `TERMINUS_TAVILY_API_KEY` / `TERMINUS_EXA_API_KEY`) |
| `TERMINUS_LLM_PROVIDER` | `none` | `openai` or `anthropic` (+ key, `TERMINUS_LLM_MODEL`; install the `agent-openai` / `agent-anthropic` extra) |
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
- **Configuration.** Settings come only from environment variables and the user's own
  `config.env`. A `.env` in the working folder is ignored, so an untrusted checkout cannot
  point Terminus at another data source or database. On Linux and macOS the data folder
  is created with mode 0700.
- **API (optional).** Bound to localhost by default. A bearer token with constant-time comparison is
  required for every `/api` route, and the API refuses requests when no token is
  configured. Only two mutating routes exist (import inventory, start scan). Responses
  carry strict security headers, there is no CORS, and errors are generic.
- **Dashboard (optional).** Bound to `127.0.0.1`, XSRF protection on, 5 MB upload cap. Untrusted
  text is rendered as plain text, never Markdown or HTML. Links are shown only for
  validated `http(s)` URLs. Operations are limited to import, scan, view and export.
- **Exports.** CSV cells are protected against spreadsheet formula injection.
- **Data.** Only synthetic sample data ships with the repository and the package. Real
  inventories live in the user's data folder, outside the repository.

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

`terminus/data/fixtures/` contains API responses recorded on the date in `manifest.json` with
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
- No scheduler yet. Run `terminus scan` (incremental) from cron or Windows Task Scheduler.
- Verified on Windows 11 and Ubuntu 24.04 (WSL2) with Python 3.12 and 3.13. macOS is
  untested.
- The LLM layer has been exercised with a scripted mock LLM in tests, not with a live
  provider in this repository's CI.

## License

MIT, see [LICENSE](LICENSE).
