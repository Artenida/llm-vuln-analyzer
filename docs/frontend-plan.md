# Frontend Plan — Web UI for LLM-Vuln-Analyzer

> **Status:** Sprints 8–11 complete (2026-08-01). The product was rescoped from
> experiment-browsing to analyze-first on the same day — see §8 — and narrowed
> again on 2026-08-11, when the History page was removed so the flow is one
> codebase, one analysis, that run's results (§10). Per-diff patch Apply landed
> the same day (§9). Sprint 12 (polish) outstanding, plus two exit criteria that
> need a live API key.
> Sprint numbering continues [`sprint-plan.md`](sprint-plan.md) (1–7 are the
> analysis engine).

---

## 1. What this UI is

**Point it at a folder, press Analyze, read the results.**

The UI is a front end for *running* the analyzer, not a browser over past
experiments. A session is:

```
pick a folder  →  choose options  →  Analyze  →  watch it run
                                                    ↓
        results: findings · call graph · coverage · cost
                                                    ↓
                            Generate patches · save wherever you want
```

Supporting screens exist because that loop needs them: a **Dashboard** for what
it all cost, and **Settings** for the API key and analysis options.

### What it is not

- **Not an experiment browser.** The datasets, ground-truth tables, evaluation
  reports and per-dataset run archives under `experiments/` are thesis
  apparatus, not the product. `evaluate` and `bootstrap-ground-truth` stay
  CLI-only. *(Reversed from the first draft of this plan, which made browsing
  the front door — see §8.)*
- **Not multi-user, not deployed, not authenticated.** It binds to
  `127.0.0.1`, drives the local filesystem and holds a local API key.
- **Not a second implementation of anything.** The web layer shells out to the
  same CLI a human would run, and reads cost from the same `CostLedger`. A run
  started from the UI produces a byte-identical run directory to one started
  from a terminal.

### Guiding constraints

| Constraint | Consequence |
|---|---|
| Not the main focus of the project | Each sprint is independently shippable. Sprint 9 alone (analyze + live progress + findings) is already the whole core loop. |
| Show every element of a result | Every field of `analysis.json`, `extraction.json`, `call_graph.json` and the patch artifact is reachable, with a raw-JSON fallback so the answer is never "you can't see it". |
| Must not look careless | One design system, defined in §4 and already built in Sprint 8. |
| Runs cost real money | No analysis starts without an explicit confirm showing a projected cost. `--budget-usd` is pre-filled, not opt-in. |
| Must never corrupt source | Nothing writes into the analyzed folder as a side effect. The one write that exists is Apply on a single reviewed diff — opt-in, confirmed, verified against the analyzed bytes, and reversible. See §9. |

---

## 2. Architecture

```
┌───────────────────────────────────────────────────────────────┐
│  Browser — React 19 + TypeScript SPA (Vite)                    │
│  Analyze · Results · Evaluations · Costs · Settings             │
└──────────────────┬────────────────────────────────────────────┘
                   │  fetch /api/*        EventSource /api/jobs/{id}/events
┌──────────────────▼────────────────────────────────────────────┐
│  FastAPI — src/web/                                            │
│    app.py           factory, SPA mount                         │
│    paths.py         root registry + traversal guard            │
│    settings_store.py  UI config  +  API key → .env             │
│    jobs.py          subprocess runner, log bus, progress parse │
│    results.py       load a result bundle from ANY directory    │
│    routers/  fs · settings · jobs · results · cost             │
└──────────────────┬────────────────────────────────────────────┘
                   │  subprocess: python -m src.cli analyze|patch
┌──────────────────▼────────────────────────────────────────────┐
│  Existing engine — unchanged except `analyze --output-dir`     │
└───────────────────────────────────────────────────────────────┘
```

### Why a subprocess and not an in-process call

The analysis loop is synchronous, long-running and paid-for. Running it as
`python -m src.cli analyze …` gives cancellation that actually works (kill the
process; the existing checkpoint saves the partial run), isolation from the web
server's event loop, and — most importantly — the guarantee that the UI cannot
drift from the CLI, because it *is* the CLI. Progress is parsed from the
per-function lines `analyze` already prints.

### Results are no longer confined to `experiments/`

The user picks where a run's output goes. `paths.py` therefore keeps a
**registry of allowed roots** (the default results directory, plus any output
directory a job has written to) instead of one hardcoded root. Artifact reads are anchored to that registry; the directory *browser* is
separately allowed to list anywhere, since browsing to a folder is its job.

---

## 3. Engine change required

`analyze` currently pins its output to `experiments/…`, chosen by
`--run-name`/`--dataset`. One flag is added:

```
analyze --output-dir <dir>    # writes extraction.json, call_graph.json,
                              # analysis.json, checkpoint.jsonl and the
                              # graph HTML/DOT into <dir>
```

It sets `config.output.{extraction,context,analysis}_folder` and uses the same
fixed filenames `--run-name` uses. `--run-name`/`--dataset` keep working exactly
as before for the thesis workflow; `--output-dir` wins if both are given.

This is a CLI improvement in its own right, not UI scaffolding — it is the only
engine change the whole UI needs.

---

## 4. Design system

Built in Sprint 8, unchanged by the rescope. Full token list in
[`frontend/src/styles/tokens.css`](../frontend/src/styles/tokens.css) — **the
only file permitted a raw colour value**, so a light theme stays a token flip.

**Direction: "instrument panel."** Dark-first, dense, monospace for anything a
machine produced (paths, identifiers, CWE ids, token counts, money),
proportional type for prose (explanations). Saturated colour is spent almost
entirely on severity and status, so on any screen the coloured things *are* the
findings.

| Group | Tokens |
|---|---|
| Surfaces | `--bg` `--surface` `--surface-2` `--surface-3` `--border` |
| Text | `--text` `--text-dim` `--text-faint` |
| Accent | `--accent` `--accent-dim` `--accent-wash` |
| Severity | `--sev-critical` `--sev-high` `--sev-medium` `--sev-low` `--sev-none` |
| Status | `--ok` `--warn` `--err` `--muted` |

**Primitives** (`frontend/src/components/`): `Card`, `StatTile`, `Badge`,
`DataTable`, `FilterBar`, `MetricBar`, `Tabs`, `EmptyState`/`ErrorState`/
`Skeleton`. Added by the rescope: `DirectoryPicker`, `LogStream`, `CodeBlock`,
`DiffView`, `Drawer`, and form fields (`TextField`, `Select`, `Toggle`).

---

## 5. Screens

### 5.1 Analyze — `/` (the front door)

| Element | Detail |
|---|---|
| **Target folder** | Free-text path **and** a Browse dialog. A browser cannot read an absolute path from a native file dialog — `<input webkitdirectory>` yields relative names only — so Browse opens a **server-side directory picker**: it lists drives and folders from the backend and you navigate to the one you want. This is the only design that gives a real path. |
| Validation | On pick: does it exist, how many source files, which languages, estimated function count. Shown before you commit. |
| **Mode** | Semantic (call-graph context) or Agentic (ReAct). Default from Settings. |
| Options | Model, max ReAct steps, max function lines, visualize (call graph HTML), dry run, resume, API key alias. |
| **Output directory** | Where results are written. Defaults to the configured results root + a generated run name; fully editable, with the same Browse dialog. |
| **Budget** | `--budget-usd`, pre-filled from Settings. |
| **Cost estimate** | Projected from the ledger's measured $/function for the chosen mode × the estimated function count. Shown in the confirm step. Says "no measured rate yet" rather than guessing when the ledger has no data for that mode. |
| **Analyze** | Confirm dialog stating projected cost and output path → job starts. |
| **Live progress** | Function counter and progress bar parsed from the CLI's own per-function output, a streaming log, running spend, and Cancel (which leaves a resumable checkpoint). |
| **Open previous results** | A path field and the same Browse dialog, for reading a run this session did not produce — an earlier session, another machine, or a plain CLI run. It points `lastResultDir` at that folder, so Results and Evaluations follow. Deliberately one action and not a list of past runs — see §11. |

### 5.2 Results — `/results?path=`

Tabs. Every field of every artifact appears somewhere.

| Tab | Contents |
|---|---|
| **Summary** | Functions analysed, findings, clean, errors, hallucinated; severity mix; coverage bar; tokens; total cost and per-phase cost; model/mode/source/output paths; partial-run banner if the run was cancelled or hit its budget. |
| **Findings** | Sortable, filterable table (severity · CWE · file · confidence · hallucinated · error · duplicate group). Row → drawer with the explanation, patch suggestion, the function's real source with `affected_lines` highlighted, per-finding tokens and cost, and the generated diff once patches exist. |
| **Call graph** | The interactive `call_graph.html` / `call_graph_annotated.html` embedded in an iframe — these are already self-contained, dark-themed and good, so re-implementing them would be waste. Beside it, a searchable node table over `call_graph.json` (callers, callees, entry point, infrastructure, external, taint source, taint sink), which is what a graph is bad at. |
| **Extraction** | Coverage bar, the `skipped_oversized[]` table, and every extracted function with its source. |
| **Patches** | **Generate patches** button → runs `patch` as a job with its own cost confirm. Then: each patch's rendered unified diff, valid/invalid, error, tokens, cost, and whether it is currently written to the source file. Generating changes nothing on disk; **Apply** on an individual diff writes that one function, and **Revert** puts it back. See §9. |
| **Raw** | Every file in the output directory, with a JSON viewer. The guarantee nothing is unreachable. |

### 5.3 Dashboard — `/dashboard`

Total spend, and spend broken down by **phase** (call-graph edge resolution ·
analysis · patch generation), by model, by API key alias, and by run — straight
from `CostLedger`, which is already the source of truth for the CLI's `cost`
command. Recent analyses with their cost. A group whose pricing is unknown
renders `n/a`, never `$0.00` — an unpriced model is not a free one.

### 5.4 Settings — `/settings`

| Group | Fields |
|---|---|
| **OpenAI** | API key (write-only — the browser is sent a masked preview and a "configured" flag, never the value), plus named aliases for multi-key setups. Persisted to `.env`, the file the CLI already reads. The UI states plainly that it is stored in plaintext locally. |
| **Analysis defaults** | Model, mode, max ReAct steps, max function lines, skip directories. |
| **Output** | Default results directory, default budget. |
| **Environment** | Read-only: project root, Python, whether a ledger exists, whether the key resolves. |

---

## 6. API

```
GET  /api/health
GET  /api/settings                 config + { api_key_configured, api_key_masked }
PUT  /api/settings                 persist config; API key written to .env
POST /api/settings/test-key        one cheap call to verify the key works

GET  /api/fs/roots                 drives / home / project
GET  /api/fs/list?path=            directories (+ source-file counts) for the picker
POST /api/fs/inspect               {path} -> exists, files, languages, est. functions
POST /api/fs/mkdir                 create an output directory the user names

POST /api/jobs/analyze             whitelisted args -> job id
POST /api/jobs/patch               {results_path} -> job id
GET  /api/jobs                     history of jobs this process knows about
GET  /api/jobs/{id}
GET  /api/jobs/{id}/events         SSE: log lines, progress, terminal state
POST /api/jobs/{id}/cancel

GET  /api/results?path=            summary of a result bundle at a directory
POST /api/results/open             {path} -> register a foreign result dir, then its summary
GET  /api/results/findings?path=
GET  /api/results/extraction?path=
GET  /api/results/graph?path=
GET  /api/results/graph.html?path= iframe target
GET  /api/results/patches?path=
GET  /api/results/source?path=&file=   function source for a finding
GET  /api/results/artifacts?path=      file list + raw JSON passthrough

GET  /api/cost                     total · by phase · by model · by key
GET  /api/cost/runs
```

**Argument safety.** Job arguments are built from a whitelist of known flags with
typed values — never string-concatenated from free text, and never passed
through a shell.

**Path safety.** Artifact reads resolve against the registry of allowed roots
(§2). The directory browser is the deliberate exception and may list anywhere,
because that is what a folder picker does; it returns names and types only,
never file contents. `POST /api/results/open` is the only way the browser can
add to that registry, and it refuses any folder that does not already hold run
artifacts — see §11.

**Secret safety.** The API key is never sent to the browser and never written to
the cost ledger, job records or logs — only its alias.

---

## 7. Sprints

### Sprint 8 — Shell and design system — **DONE (2026-08-01)**

FastAPI app factory + SPA serving, design tokens, the primitive set, app shell,
`python -m src.cli ui`. Retained wholesale by the rescope. The dataset and
experiment-browsing pages built in this sprint are removed in 9 (§8).

### Sprint 9 — The analyze loop

- **9.1** Engine: `analyze --output-dir` (§3).
- **9.2** `settings_store.py` — config persistence + API key to `.env`; settings API.
- **9.3** `fs.py` — directory roots, listing, inspect (file/language/function estimate).
- **9.4** `jobs.py` — whitelisted subprocess runner, log capture, progress parsing,
  cancel, SSE bus, output-directory registry.
- **9.5** Frontend: `DirectoryPicker`, form primitives, `LogStream`.
- **9.6** **Analyze page** end to end: pick → options → cost confirm → live run.
- **9.7** Settings page.
- **9.8** Remove the Datasets / Dataset detail / experiment-browsing pages.

**Exit criteria — met 2026-08-01**
- [x] A folder can be chosen without typing a path, and analysed, without ever leaving the UI
- [x] Output goes exactly where the user chose — verified with an explicit
      `--output-dir` and with the auto-named default
- [x] Live progress and log match what the CLI prints — SSE verified end to end
      (20 events: `started` → 17 × `log` → `finished`)
- [x] Cancel stops the run cleanly — verified against a 379-function tree:
      second launch refused with 409, cancel returns exit 130, no traceback in
      the log. **See the SIGBREAK note below.**
- [x] No analysis starts without a confirm showing projected cost
- [x] The API key can be set in the UI and is never returned to the browser —
      only `configured` and a masked preview

**Bug found and fixed while verifying cancellation.** The first cancel attempt
exited `0xC000013A`. On Windows, `CREATE_NEW_PROCESS_GROUP` disables
`CTRL_C_EVENT` for the child, so `CTRL_BREAK_EVENT` is the only signal that can
reach it — but Python's default `SIGBREAK` handler *terminates the process
outright* rather than raising `KeyboardInterrupt`. The partial-run save in
`analyze` would therefore never have run, discarding every function already
analysed and paid for. `src/cli.py` now installs a `SIGBREAK` handler that
raises `KeyboardInterrupt`, and the entry point catches it for the phases with
nothing to save. Verified by comparison: without the handler, cleanup is skipped
(exit `0xC000013A`); with it, cleanup runs (exit 0).

*Still unproven:* that a cancel **mid-analysis-loop** writes a resumable
checkpoint. Demonstrating it needs a real paid run — the mechanism is verified,
the end-to-end case is not.

### Sprint 10 — Results

- **10.1** `results.py` + endpoints reading a bundle from any directory.
- **10.2** `CodeBlock` (line numbers, highlighted `affected_lines`), `DiffView`, `Drawer`, `JsonViewer`.
- **10.3** Summary and Findings tabs.
- **10.4** Call graph tab — embedded HTML + node table.
- **10.5** Extraction tab — coverage and oversized skips.
- **10.6** Raw tab.

**Exit criteria — met 2026-08-01**
- [x] Every field of `analysis.json` is visible somewhere (Findings table,
      detail drawer, or the Raw tab)
- [x] `affected_lines` are highlighted over the function's real source —
      verified against the juice-shop run: 5/5 sampled findings resolved their
      source and every flagged line fell inside the function's range
- [x] The interactive call graph renders inside the page (`call_graph.html`
      served for the iframe, 200 / `text/html`)
- [x] Skipped oversized functions are visible, so coverage is never quoted over
      an unstated denominator

### Sprint 11 — Patches and Dashboard

- **11.1** Patch job + Patches tab with rendered diffs and validity.
- **11.2** Dashboard: total and per-phase cost, by model, by key, by run.
- **11.3** Output-directory registry. *(A History page was built here and
  removed later — see §10.)*

**Exit criteria**
- [x] Patches generate from a button and render as diffs; generating leaves the
      source untouched (bulk `--apply` is still unreachable from the web layer —
      per-diff Apply, added later, is the only write; see §9)
- [x] Dashboard figures come from `CostLedger` directly, so they cannot diverge
      from `python -m src.cli cost`; `n/a` groups are preserved
- [x] A result written outside `experiments/` is still readable — the job
      runner registers its output directory, which is what authorises the read
- [ ] A patch run driven from the UI end to end — needs a live key, same gap as
      the mid-loop cancel above

### Sprint 12 — Polish

Keyboard navigation, light theme via the token flip, responsive layout,
`pytest` coverage for `paths.py`, `jobs.py` argument building and the routers,
a `vite build` step wired into `ui`, thesis screenshots.

---

## 8. Decisions and exclusions

| Decision | Reasoning |
|---|---|
| **Analyze-first, not browse-first** | Rescoped 2026-08-01 on the user's instruction: the UI's purpose is running an analysis on a chosen folder, not reviewing the experiment archive. The dataset / ground-truth / evaluation pages built in Sprint 8 are removed. The engine work behind them is untouched and the pages could return as a separate section if wanted. |
| **`evaluate` stays CLI-only** | Scoring against ground truth is thesis apparatus, and only applies to the curated datasets — not to an arbitrary folder a user points at. |
| **Server-side directory picker** | A web page cannot obtain an absolute path from a native file dialog. Since the backend is local, listing directories server-side is the only way "select the folder" can actually work. |
| **Subprocess, not in-process analysis** | Real cancellation, no event-loop blocking, and the UI cannot drift from the CLI because it *is* the CLI. |
| **API key in `.env`** | The file the CLI already reads, so a key set in the UI works in the terminal too. Stored in plaintext, which the Settings page says outright. Never returned to the browser. |
| **Iframe the existing call graph** | `export_graph.py` already emits a self-contained interactive graph with taint and severity colouring. Re-implementing it in React would cost days for nothing. |
| **Per-diff Apply, never bulk apply** | Superseded the earlier "`patch --apply` stays CLI-only" exclusion, on request: a user who has read a diff and wants that fix should be able to take it. What the original reasoning was actually protecting against was the *implicit* write — a whole run applied as a side effect of generating patches. So the bulk path stays CLI-only and the UI writes one reviewed function at a time. See §9. |
| **No auth, binds to localhost** | Single-user local instrument. Auth implies a deployment story that does not exist. |
| **No server-side pagination** | The largest artifact is a few hundred rows; one fetch plus client filtering is simpler and faster. |
| **Call-graph assets are vendored, not CDN** | pyvis emits a page that loads vis-network from a CDN, references `lib/` relatively, and points at a `node_modules/vis` tree this project does not have. None of that survives being served from an API URL — the relative paths fall through to the SPA catch-all and the browser gets HTML where it expected JavaScript. `/api/results/graph.html` rewrites those references to `/vendor/`, backed by the `lib/` already in the repo, and strips the CDN Subresource Integrity hashes (which no longer match the local files and would otherwise block the script). The graph now renders in the iframe with no internet at all. |
| **Analyze form state lives above the router** | `frontend/src/state/AnalyzeForm.tsx`, mirrored to localStorage. A page-local `useState` is destroyed on navigation, which threw away a picked path and a scan that took seconds. Settings defaults seed it once — re-applying them per mount would overwrite the user's own choices. |
| **Deliberately not surfaced** | Nothing. Any field that ends up unsurfaced must be listed here with a reason — the Raw tab exists so the answer is never "you can't see it". |

### Browser verification

Sprints 9–11 were signed off on API-level checks, which passed while the UI was
visibly broken — the graph endpoint returned `200 text/html` for a page that
rendered nothing. Front-end changes are now checked by driving a real browser
(Playwright): form state across navigation and reload, progress reaching 100%
and surviving a reconnect, `Results` opening the latest run, the call graph
actually painting a canvas, and a zero-console-error assertion. The harness
lives outside the repo; promoting it to a checked-in test suite is open.

---

## 9. Applying a patch to the analysed project

The Patches tab can write a generated fix into the source file it came from.
This is the only place the web layer modifies a file outside a result
directory, and it reverses the original "`patch --apply` stays CLI-only"
exclusion in §8 — deliberately, on request, and with the reasoning behind that
exclusion preserved rather than discarded.

The thing that rule was protecting against is the **implicit** write: a whole
run applied to disk as a side effect of generating patches, or of opening a
page. That has not changed. What is now allowed is the explicit one: a user
reads a specific diff and chooses to take that specific fix.

### The shape of it

`src/web/patch_apply.py`, behind `POST /api/results/patches/apply` and
`/revert`. One function per request; there is no bulk endpoint to reach for by
accident, and `patch --apply` is still the way to write a whole run at once.

In the UI: open a diff from the Patches table → **Apply to source file** → a
confirm step that names the file being overwritten → applied. The table gains a
*Source file* column (`unchanged` / `applied` / `reverted`) so the state of the
project is readable without opening anything.

### What it refuses, and why

| Guard | Without it |
|---|---|
| `patch_valid` must be `true` | A diff that failed the tree-sitter parse check would be written as a "fix" that does not compile. |
| Target must resolve inside the run's own `source_path` | `file_path` arrives on the request. Without containment the endpoint is a write-anywhere oracle. |
| File content must match `extraction.json` byte for byte | The recorded line range still points *somewhere* after the file is edited — at unrelated code. This is the difference between a patch and a deletion. |
| The function is located by content, not by line number | Applying one patch shifts every function below it in the same file, so by the second apply the recorded range is stale. Content matching absorbs the drift; the recorded line is only a hint. |
| Two identical bodies → refuse | There is no single correct place to write, so nothing is written. |
| Line endings and first-line indent are taken from the file | tree-sitter records a node from its first *column*, so an indented function's extracted source has no leading indent on line one while the file does — dropping it breaks the enclosing block, fatally in Python. Splicing LF text into a CRLF file turns one fix into a whole-file diff. |

### Reversibility

Every applied patch is journalled to `patches_applied.json` in the **result**
directory, holding the exact bytes on both sides of the edit. That is what
Revert restores, and keeping it with the results rather than as a `.bak` beside
the user's code means applying a fix leaves nothing behind in their project but
the fix itself. Reverted entries are kept, not deleted: "applied and undone" is
a different fact from "never applied".

The file is deliberately **not** named `applied_patches.json` — `patch_file()`
finds a run's patch artifact with a `*_patches.json` glob and takes the newest
match, so that name made the journal shadow the patch document itself on the
first apply. `results.patch_file()` now also excludes it by name.

Covered by `tests/test_patch_apply.py` (17 tests, weighted towards the refusals:
a wrong write here corrupts a source tree while looking like a successful fix).
**Not yet checked in a real browser** — see *Browser verification* above; the
API path and the engine are tested, the rendered control is not.

---

## 10. History removed — the flow is one run

The UI kept a list of every analysis it could find: a **History** page, a
`history.json` in `.vulnui/`, `GET|POST|DELETE /api/history`, and a workspace
scan that merged recorded entries with any result folder it discovered. Removed
on request. The flow is meant to be one thing:

```
pick a codebase  →  analyze  →  read that run's results
```

A list of previous runs is a second, competing way to navigate, and it pulled
the product back towards the experiment browser the rescope in §8 already
rejected once.

### What replaced it

One pointer, `lastResultDir`, in the Analyze form state
(`frontend/src/state/AnalyzeForm.tsx`, mirrored to localStorage like the rest of
that state). It is set from `job.output_dir` whenever a job is known — started
here, adopted from the active-job poll after a refresh, or finished. **Results**
and **Evaluations** open on it when no `?path` is given; both still accept an
explicit `?path`, so a run is still linkable and the two pages stay in step.

Evaluations loses its run picker with it — there is no list to pick from. It now
shows which run it is scoring and a link across to Results.

### What deliberately stayed

**`paths.register_root()` and the root registry.** This is easy to mistake for
part of History and it is not: it is the *authorisation* for reading a result.
Artifact reads are confined to directories this tool has written to, so the job
runner must still register an output directory when a run finishes, or the run
that just completed could not be read back. It records where a result is, never
a copy of it, and nothing lists it.

That split is also what makes the last run survive a **server restart**: the
pointer is in the browser's localStorage, the read authorisation is in
`roots.json`, and neither needed a history list to work.

### Consequences worth knowing

* An existing `.vulnui/history.json` is now dead. Nothing reads or writes it; it
  is left in place rather than deleted, since it is the user's file.
* **Results produced elsewhere were no longer openable.** `POST /api/history/open`
  was the recovery path for a result from another machine, a lost registry, or a
  CLI run, and it went with the rest. It did turn out to matter, and came back
  exactly as this section predicted — one action on the Analyze page, not a list
  of past runs. See §11.
* `Runs billed` on the Costs page counts ledger rows rather than history rows.
  The ledger is the same source `python -m src.cli cost` uses, so the figure
  still cannot disagree with the CLI.

---

## 11. Opening a results folder from a previous run

**Open previous results** on the Analyze page: a path field, the same Browse
dialog, and an Open button that takes you straight to Results for that folder.
It is the recovery path §10 removed with the History page and predicted would
come back — a run from an earlier session, a folder copied off another machine,
or output from a plain `python -m src.cli analyze`.

It is deliberately *not* the History page returning. There is no list, nothing is
enumerated, and nothing is recorded beyond the single `lastResultDir` pointer
that already existed. You name a folder; that folder becomes the run the session
is reading, and Results and Evaluations both follow it, exactly as they do after
a live run.

### Why it needs a server call at all

The obvious implementation — set `lastResultDir` in the browser and navigate —
does not work, and the reason is the point of the feature. Artifact reads are
authorised against the registry of directories this tool has written to (§2), so
a folder it has never seen returns `400 not a known result location` no matter
what the URL says. `POST /api/results/open` is what adds it.

### What it refuses, and why

| Guard | Without it |
|---|---|
| The folder must already contain `analysis.json`, `extraction.json` or `call_graph.json` | The endpoint would register *any* directory on request, which is the whole containment rule deleted by one POST. Pointing the dialog at a home folder would authorise reads inside it. |
| The directory itself is registered, never its parent | Opening one run would make every sibling run — and everything else in that parent — readable. |
| Reads stay restricted to `paths.RUN_ARTIFACTS` afterwards | A results folder can sit anywhere, including beside files that are none of this tool's business. A registered directory is not a readable directory; it is a directory whose *run artifacts* are readable. The Raw tab still lists other files by name, with `readable: false`, so the folder is never misrepresented. |

The picker helps rather than waiting to refuse: `GET /api/fs/list` reports
`is_result_dir` for the folder being listed as well as for its children, and the
dialog disables its confirm button, with the reason stated, until you are
standing in a folder that holds results.

Covered by `tests/test_web_open_results.py` (8 tests, weighted towards the
refusals). **Not yet checked in a real browser** — same gap as §9.

---

## 12. One UI server at a time

`ui` refuses to start when a UI server is already running, and prints the pid,
address and start time of the one that is. `--replace` stops it and takes over.

This is not tidiness. Nothing previously stopped a second server, so every
restart that did not shut down cleanly left the old one alive: **seventeen**
accumulated on ports 8123–8162 in one evening. None of them spends money by
itself, but each is a live endpoint that can launch a paid analysis job, and the
job it launches outlives it — a Juice Shop run started from one of them was
still billing four days later, long after every window that could have stopped
it was closed.

`src/web/instance_lock.py` holds the guard. The lock file in `.vulnui/` records
pid, host and port, and a server counts as running only when the pid is alive
**and** its port is still bound. Both signals are required because either alone
fails in a way that makes the guard worse than nothing:

| Signal alone | Failure |
|---|---|
| pid | A server killed without releasing its lock would lock the user out of ever starting another — the exact state a force-kill leaves behind. Pids are also recycled, so a stale entry eventually names an unrelated process. |
| port | Misses the case that caused this. Those seventeen servers were each on a *different* port, so nothing collided. |

The requested port is then checked separately, so "something else is on 8000"
gets its own message rather than a uvicorn `address already in use` traceback.

`pid_alive()` deliberately avoids `os.kill(pid, 0)`, the POSIX idiom for this:
on Windows `os.kill` maps onto `TerminateProcess`, so the liveness check would
kill the process it was asking about. It uses `OpenProcess` +
`GetExitCodeProcess` there and `os.kill` only on POSIX.

Covered by `tests/test_instance_lock.py` (12 tests), and verified end to end:
a second start on the same port and on a different port both refuse,
`--replace` takes over, and a hard-killed server's stale lock does not block the
next start.
