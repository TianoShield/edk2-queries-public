# edk2-queries — Agent Guide

## Purpose

This repository contains CodeQL queries that detect security vulnerabilities in
[EDK2](https://github.com/tianocore/edk2) UEFI firmware.  Queries target either:
known CVEs or other bug patterns not directly related to a CVE.

In both cases the goal is **generic** and **precise** detection:

- **Generic** — catch the root cause, not the surface syntax.  A query that
  only matches one function name or one file will miss variants.  Prefer
  dataflow / taint tracking, `GuardCondition`, and structural properties of the
  IR.  Avoid hardcoding identifier names, `toString()` substring matching, or
  line-number comparisons.
- **Precise** — false positives must be minimised.  Add sanitisers and
  guard-condition barriers to suppress paths that are demonstrably safe.

---

## Repository layout

```
edk2-queries/
├── AGENTS.md              # this file
├── qlpack.yml             # main CodeQL pack
├── default-queries.qls     # default query suite
├── lib/                   # reusable models grouped by EDK2 package
│   ├── CryptoPkg/
│   ├── MdeModulePkg/
│   ├── MdePkg/
│   ├── NetworkPkg/
│   └── SecurityPkg/
├── test/                  # query and model tests
│   ├── <query-name>/      # test.c, .qlref, and .expected files
│   ├── edk2-*/            # focused reusable-model tests
│   └── include/           # shared simplified EDK2 fixtures
└── *.ql                   # security queries
```

Queries with companion unit tests use a directory of the same name under
`test/`. Focused reusable-model tests use an `edk2-*` directory.

### Model organization

- Put each model under the package that defines the modeled API or type, in
  `lib/<PackageName>/` (e.g. `lib/MdePkg/`, `lib/MdeModulePkg/`,
  `lib/SecurityPkg/`, `lib/NetworkPkg/`).
- Name `.qll` files after the modeled API, struct family, library, or logical
  concept — prefer a basename from the EDK2 source tree, but it is not required.
- Keep one model file per coherent ownership boundary: split when the APIs come
  from unrelated libraries or packages, group them when one logical surface is
  spread across several `.c` files.
- Import models by their package path, e.g. `import lib.MdePkg.BaseMemoryLib`
  or `import lib.NetworkPkg.NetBuffer`.
- Examples:
  - `NetworkPkg/Library/DxeNetLib/NetBuffer.c` → `lib/NetworkPkg/NetBuffer.qll`
  - `NetworkPkg/Include/Library/NetLib.h` → `lib/NetworkPkg/NetLib.qll`
  - `MdePkg/Include/Library/BaseLib.h` (strings) → `lib/MdePkg/BaseLibString.qll`

### Test fixture naming

- When a test copies or simplifies EDK2 implementation code, place that copied
  source under `test/include/{basename}.c`, where `{basename}` usually matches
  the EDK2 source file copied or simplified by the fixture.
- Prefer splitting shared copied support by EDK2 file of origin, for example
  `test/include/NetBuffer.c`, `test/include/LinkedList.c`, and
  `test/include/HttpsSupport.c`, instead of one catch-all support header.

---

## Running queries

Run a single query and write SARIF output:

```bash
codeql database analyze \
  --rerun \
  --additional-packs=. \
  --format=sarifv2.1.0 \
  --output=analysis.sarif \
  path/to/codeql-database \
  ArithmeticTainted.ql
```

Save output outside the database directory so generated files do not enter the
database tree. Always pass `--rerun` after code changes; without it, CodeQL
returns cached results.

---

## Testing queries

### Test structure

Each companion query-test directory under `test/` contains:

- `test.c` — C test cases.  Functions named `*_BAD` demonstrate the vulnerable
  pattern and must produce at least one alert.  Functions named `*_GOOD`
  demonstrate sanitised / patched code and must produce **zero** alerts.
- `<query-name>.qlref` — one line naming the root query file, for example
  `TaintedNullTerminatedStringFunction.ql`.
- `<query-name>.expected` — accepted query output (managed by `--learn`).

### Test case authoring

- Include **multiple BAD variants** that exercise different code paths leading
  to the same root cause (e.g. taint via `NetbufGetByte`, via `NetbufCopy`,
  via field access).  Semantic-preserving mutations (reordering assignments,
  renaming locals, using intermediate pointers) are encouraged to verify the
  query is not pattern-matching syntax.
- Include **GOOD cases** for every sanitiser or fix pattern (e.g. explicit null
  termination, length-bounded copy, guard check).
- Stubs for EDK2 types and library functions go at the top of `test.c`; keep
  them minimal.

### Running tests

```bash
# Run once and check against accepted output
codeql test run \
  --additional-packs=. \
  test/ArithmeticTainted/

# Run all tests
codeql test run \
  --additional-packs=. --threads=8 \
  test/

# Accept new / changed output as the new baseline
codeql test run \
  --learn \
  --additional-packs=. \
  test/ArithmeticTainted/
```

After **every code change**, run **all relevant tests before reporting back**:
- If only one query and its local tests changed, run that query's test dir.
- If shared libraries under `lib/` changed, run `codeql test run --additional-packs=. test/`.
- If multiple queries or shared expectations changed, run `codeql test run --additional-packs=. test/`.
- Do not wait for the user to ask for tests; test proactively.

**Before running `--learn`**, inspect the diff output to confirm the actual
results are correct.  `--learn` unconditionally overwrites the expected file,
so accepting wrong output silently hides regressions.  Check that:
- every line prefixed `+` in the diff is a genuine new TP (or expected
  provenance change), not a false positive;
- every line prefixed `-` is a deliberate removal (e.g. a renamed test or a
  suppressed FP), not a missing TP.

Always verify after `--learn`: all BAD cases produce alerts; all GOOD cases produce none.

---

## Query design principles

1. **CVE queries: alert on the vuln, silence the fix, triage the rest** — when
   extending a query or its libraries (including taint models) to detect a CVE,
   the query must alert on the vulnerable source tree and stay silent on the
   patched source tree. If the extension introduces alerts beyond the CVE
   itself, triage each new alert into TP / FP, then refine the query to
   eliminate the FPs as far as possible.

2. **Use taint / dataflow** — model sources, sinks, sanitisers, and additional
   flow steps rather than matching AST patterns.  Use
   `TaintTracking::Global<Config>` for path-problem queries.

3. **Prefer reusable model classes** — use `TaintFunction`,
   `DataFlowFunction`, `ArrayFunction`, and `TaintInheritingContent` whenever
   possible, since those models apply to all queries that use the standard
   libraries. EDK2-specific reusable models live in `lib/*.qll`. Use a
   query-specific `isAdditionalFlowStep` only when the flow cannot be modeled
   cleanly with those shared abstractions.

4. **Model every taint source as a `RemoteFlowSource` / `LocalFlowSource`** —
   define attacker-controlled entry points by subclassing `RemoteFlowSource`
   (remote/network input) or `LocalFlowSource` in a `lib/*.qll` file, each with a
   `getSourceType()` provenance string. Never introduce a query-local source
   predicate. A shared `FlowSource` subclass is picked up by every query whose
   configuration uses `FS::FlowSource`, so a new entry point is modeled once and
   reused; the query's own source predicate stays the trivial
   `source.getSourceType() = sourceType`. When the source is not a plain
   parameter/return but a cached or re-read buffer the dataflow library cannot
   reach from the true origin (e.g. the CVE-2023-45235 PXE BC offer copied into
   private data across an indirect protocol callback), document why in the
   `FlowSource` subclass and still model it there, not in the query.

5. **Use `GuardCondition` to encode dominating checks** — when a check (e.g. a
   length comparison or null test) provably constrains a value on the path to a
   sink, encode it with `GuardCondition` so it applies everywhere the check
   dominates, not just the one code location you noticed. The same machinery
   serves two roles: a **barrier** that suppresses a flow whose value a guard
   already sanitises (e.g. the `isUpperBoundGuarded` upper-bound barrier in
   `TaintedBaseMemoryLibLength`), or a **guard-aware sink** that fires an
   operation only when no dominating guard bounds it (e.g. the unguarded
   unsigned-subtraction underflow sink in `ArithmeticTainted`).

6. **No hardcoded names in query logic** — identifiers like function names
   belong in model classes or shared library files, not in `where` clauses.
   This makes adding new variants a matter of extending a model, not editing
   query logic.

7. **Comment non-obvious logic** — add comments only where the CodeQL logic is
   not obvious from the code itself. Prefer short comments that explain why a
   predicate or model exists, what flow it captures, or what precision tradeoff
   it enforces. Do not narrate trivial syntax. Use `//` inline comments in
   `.ql` and `.qll` only for difficult-to-understand parts of the logic.

### QL / QLL comment guidance

- Put QLDoc on the class or predicate declaration it documents, not on the
  constructor body.
- In `.ql` query files, every predicate should have QLDoc.
- For subclasses of `TaintFunction` or `DataFlowFunction` document:
  - the modeled function prototype
  - the exact flow that is added, for example `arg[*1] -> arg[*3]` or
    `arg[*0] -> return[*1]`
  - why that flow is justified by the real EDK2 implementation
- For subclasses of `TaintInheritingContent`, document:
  - the struct definition or the relevant part of it
  - which fields inherit taint
  - whether the taint applies to the field value itself or the pointee reached
    through that field

---

## Commit style

```
<ql/qll-filename>: <short summary (imperative, ≤72 chars)>

<body: what was changed and why, wrapped at 72 chars.
```

**Subject examples:**

```
TaintedNullTerminatedStringFunction: add StrCpyS family as sinks
MdePkg/BaseLibString: add StrCmp, StrStr, Print, SPrint models
TaintedBaseMemoryLibLength: initial query for CVE-2024-38805
all: move struct-field taint steps into reusable TaintInheritingContent
test: share Netbuf test support across query test cases
```

**Body guidance:**

- If a commit spans multiple parts of the repo, structure the body as one
  paragraph per change area, each led by a `<path>: ` or `<area>: ` prefix
  matching the touched files. Example prefixes: `lib/MdePkg/PeImage.qll:`,
  `ArithmeticTainted.ql:`, `Tests:`.
- Keep each paragraph tight — one or two sentences stating exactly what
  changed and why. Do not write too many low-level details.
- Quote identifiers in backticks (`peCoffLoaderImageContextFieldWriteStep`,
  `Section->Misc.VirtualSize`) so they stand out from prose.
- Describe changes **relative to what is actually in git history**, not
  relative to intermediate working-copy states that were never committed.
- Use real line breaks in the commit body; never include literal `\n`
  sequences in the message text.
- End the body with one sentence stating how the commit was verified, for
  example that all relevant unit tests pass (`codeql test run`).
