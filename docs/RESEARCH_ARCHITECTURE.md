# Kavach.ai static extraction, slicing, and learning pipeline

**Technical handoff for review — 13 August 2026**

## Purpose and current research question

Kavach.ai is a prototype for learning an Android malware signal from statically extracted code. The current work is not intended to prove that a suspicious API call is malicious. It asks a narrower question:

> **Do our sink-centred backward slices preserve enough malicious/benign behavioural context for a classifier to learn a useful distinction?**

We want review primarily of the extraction, CFG, dependency, and slicing choices described below. We also need advice on weak slice labels, severe slice-level class imbalance, dataset provenance/coverage, redundancy, and how to validate slice informativeness before investing further in model tuning.

```text
labelled APK
    ↓
APKTool Smali extraction ── raw-DEX fallback when incomplete
    ↓
versioned static IR: methods, instructions, labels, payloads, handlers
    ↓
configured suspicious API matches (sinks)
    ↓
instruction CFG + bounded backward data/control traversal
    ↓
one normalized text slice per selected sink
    ↓
SecureBERT 2.0 + LoRA binary slice classifier
    ↓
[not implemented/evaluated here] APK-level aggregation
```

The present corpus is a prototype corpus. Generalization to unseen malware families, time periods, stores, or obfuscators has not been established.

## 1. APK to reusable static representation

### 1.1 Corpus inventory and APK validation

The offline builder inventories files under `data/Benign/` and `data/Malicious/`. The directory supplies the APK label. It computes SHA-256 identities, removes duplicate APK hashes, records file size/source path, and creates a fixed 70/15/15 train/validation/test split at APK-hash level (seed 42). Exact APKs therefore cannot cross splits.

The metadata contains only label, hash, size, and local source path. It does **not** record family, collection source/date, package/library provenance, signer, or label consensus. Older claims of broad multi-source/family coverage are therefore not verifiable from current artifacts ([build_dataset.py](training/build_dataset.py), [apk_metadata.jsonl](training/data/manifests/apk_metadata.jsonl)).

A separate production triage component parses manifest and lightweight code signals into a prioritization score, not a verdict. **Its result is not consumed by the slice dataset or classifier**; manifest and component/lifecycle context are absent from model input ([triage.py](kavach_ai/backend/pipeline/stage1_triage/triage.py)).

### 1.2 Code extraction

The extractor validates the APK ZIP, inventories all `classes*.dex` files and native libraries, and creates an APK-hash workspace. APKTool disassembles each DEX into its corresponding Smali directory. The in-repository parser converts method bodies into backend-neutral `ExtractedMethod` objects containing:

- class, method, descriptor, access flags, parameter slots, and register/local counts;
- ordered instructions with opcode, operands, raw text, instruction index, and offset where available;
- labels, packed/sparse-switch and array-data payloads;
- exception-handler ranges and targets;
- extraction backend and structured parse issues.

CFG/slicing uses only valid, non-native/non-abstract methods with parsed instructions. If APKTool is incomplete or misses DEX coverage, Androguard parses raw DEX and recovered methods are merged. Partial/failed APKs are excluded.

JADX support exists as a side analysis, but `run_jadx_analysis=False` was used for this offline dataset. Java source from JADX does not enter the IR or slices. This corrects older high-level architecture descriptions that may imply JADX participates in the training representation ([decompile.py](kavach_ai/backend/pipeline/stage2_static/decompile.py), [dataset_v1.json](training/data/manifests/dataset_v1.json)).

### 1.3 Static IR and reuse boundary

Versioned `static-ir-v1` stores methods, extraction status/issues, and JNI results without filesystem paths/symbol addresses. Slicing/tokenization can be rebuilt without APKTool.

JNI analysis is cached but not joined into slices; native calls end at typed boundaries. The reuse boundary is:

```text
APK → reusable static IR → fixed slicer implementation/policy → slice shard → token shard
```

Sink rules, limits, normalization, selection, and tokenization are downstream of the IR, although multiple slicing policies are not yet exposed through a clean configuration surface ([static_ir.py](training/utils/static_ir.py), [jni_bridge.py](kavach_ai/backend/pipeline/stage2_static/jni_bridge.py)).

## 2. Sink detection: where slicing starts

A sink is an `invoke-*` instruction whose referenced class and method match a configured rule; descriptors are checked where the rule specifies one. This is syntactic exact matching over usable extracted methods. It is not taint analysis and does not require a known sensitive source.

| Category | Current matched behaviours |
|---|---|
| Reflection | `Class.forName`, `Class.getMethod`, `Method.invoke` |
| Class loading | `DexClassLoader` construction/loading, `ClassLoader.loadClass` |
| Native loading | `System.load`, `System.loadLibrary` |
| Execution | `Runtime.exec`, `ProcessBuilder.start` |
| Accessibility | global action, gesture dispatch, accessibility-node action |
| SMS | `SmsManager.sendTextMessage` |

There are 14 rules in total. Several rules intentionally accept any overload because their descriptor is unset; others require an exact descriptor. Constructor reflection, path/in-memory class loaders, network/file APIs, cryptography, device identifiers, intents/ICC, package installation, and many other potentially security-relevant APIs are not sink rules today.

The architectural assumption is that these calls are useful anchors for behaviour likely to matter to malware analysis. They are **not positive labels**. Benign applications legitimately use all six categories. The classifier is expected to infer whether the retained context resembles malicious or legitimate use ([slicing.py](kavach_ai/backend/pipeline/stage3_ml/slicing.py)).

> [!important] Tunable assumption: the sink catalogue
> The current catalogue is an experimental design choice, not a complete or fixed definition of security-sensitive Android behaviour. Review may motivate adding missing categories, removing/refining noisy sinks, splitting broad categories, matching API combinations/chains, or ranking sinks by expected information value. These are open experiment dimensions, not implemented features.

Before slicing, sinks are grouped by category and selected in deterministic round-robin order, up to 256 per APK. This avoids allowing a single category to consume every slot, but it does not rank sinks by risk or information content. Across the corpus, 13,849 detected sinks were omitted by this cap.

## 3. CFG construction

The slicer builds one instruction-level CFG for every usable method. Nodes are instruction indices. Implemented edges are:

- ordinary fallthrough;
- conditional branch target plus fallthrough;
- unconditional `goto` target;
- all targets in packed/sparse-switch payloads plus fallthrough;
- exception edges from every instruction in a protected range to its handler.

`return` and `throw` terminate normal fallthrough. Unresolved branch labels, switch payloads, and handlers produce structured warnings rather than invented edges.

Important approximation: control dependency is **not** computed with post-dominators or a program-dependence graph. After data slicing, the implementation retains an `if` or switch when any already-retained instruction is reachable from that branch. It then backward-slices the condition operands. This conservative reachability rule can over-retain conditions and does not establish that the retained statement is control-dependent on the branch in the formal sense.

The CFG is method-local. Android lifecycle/callback ordering, inter-component communication, asynchronous callbacks, framework-generated calls, and manifest-derived entry edges are not represented.

## 4. Backward slicing logic

### 4.1 Intraprocedural data traversal

For each sink, the sink instruction is always retained. The initial dependency set is the set of registers used by that invocation. Traversal proceeds backward through CFG predecessors with state `(method, instruction, relevant symbolic locations, depth, incoming call context)`.

At an instruction:

1. Compute symbolic uses and definitions from the Dalvik opcode.
2. Retain the instruction if it is the traversal start or defines something currently relevant.
3. Remove satisfied definitions from the relevant set and add the retained instruction's uses.
4. Continue through every CFG predecessor.

The use/definition model covers common Dalvik moves, values, calls, fields/arrays, operations, conditions, and exits. An unknown opcode contributes its registers as uses but no definition. Unknown-opcode counts and malformed `move-result`/parameter mappings are recorded.

Symbolic memory precision is limited:

- registers are tracked directly;
- a field is one location keyed by full field signature, with no receiver/object sensitivity;
- an array is one location keyed by its array register, with no index sensitivity;
- no general points-to/alias analysis models heap objects;
- implicit information flow is not modeled beyond retained branch conditions.

A slice can contain value creation, transformations/returns, governing conditions, and the sink anchor. It is selected causal context—not a complete trace or source-to-sink proof.

### 4.2 Interprocedural traversal

For relevant return values, traversal enters extracted static/direct or unambiguous `super` callees, slices backward from non-void returns, and maps required parameters to caller registers. Parameters reaching an entry without known context can trigger bounded reverse-caller traversal.

The implementation deliberately does not resolve:

- virtual or interface dispatch;
- runtime reflection targets;
- external/framework calls without extracted bodies;
- native method bodies;
- ambiguous `super` dispatch.

These cases create typed `[BOUNDARY]` records. Recursion also stops at a boundary. For multiple matching method bodies or reverse caller sites, only the first four deterministic candidates are explored. This limits cost but may select candidates for lexical/dex ordering rather than semantic relevance.

### 4.3 Current hard bounds

| Bound | Current default | Why it exists | Concern visible in current corpus |
|---|---|---|---|
| Call depth | 3 | Bound interprocedural expansion | 7,207 slices record this limit |
| Methods per slice | 8 | Limit cross-method breadth | 2,638 limit hits; involved-method p99 is 8 |
| Instructions per slice | 256 | Bound slice size | Only 12 hits; not the primary limiter |
| Candidate callees/callers | 4 | Bound ambiguous expansion | 3,253 slices record this limit |
| Traversal states per slice | 4,096 | Stop path/dependency explosion | 8,573 hits; most frequent limit |
| Slices per APK | 256 | Bound APK contribution | 115 APKs capped, 107 benign |
| Retained slice instructions per APK | 65,536 | Bound aggregate work | No reported corpus cap from this bound |
| Slicing time per APK | 300 s | Isolate pathological APKs | No reported corpus timeout |

> [!warning] Bound pressure
> **13,507 of 97,885 slices (13.80%) are internally truncated.** Limit counts overlap. The traversal-state limit is recorded on **8,573** slices, compared with only **12** instruction-limit hits. Truncation is uneven: SMS 42.55%, execution 20.17%, and reflection 14.58%. Truncated slices are excluded from the serious training configurations.

## 5. What reaches SecureBERT

### 5.1 Slice serialization and normalization

Retained instructions are sorted by method identity and instruction index. The normalized text adds a `[METHOD] <full_signature>` marker when the active method changes and a `[BOUNDARY] kind=... target=...` marker at unresolved boundaries.

Normalization renames local `v` registers and labels by first appearance over the **full original method**, which keeps the mapping stable across slices from that method. Parameter registers (`pN`), quoted literals, method/field/type signatures, opcodes, and operands are preserved. Raw and normalized text are both stored, but the normalized form is tokenized for training.

SecureBERT receives a linear sequence: CFG edges, retention reasons, sink distance, and explicit def-use links are absent. Without instruction-to-token offsets, the loader cannot locate the sink in token space.

### 5.2 Token context

The local SecureBERT 2.0 base checkpoint is a 22-layer ModernBERT model with hidden size 768, 12 attention heads, and an architectural maximum of 8,192 positions. Current serious-run configuration nevertheless limits each example to 1,024 tokens for training cost. The only implemented policy keeps the sequence head and discards the tail.

> [!warning] Context loss
> **20,663 slices (21.11%) exceed 1,024 tokens.** The median affected slice retains about 47%. Because serialization is ordered by method identity/instruction index, head truncation does **not** guarantee preservation of the sink or its nearest context. Sink-centred windowing is unimplemented because sink token spans were not stored ([normalization.py](kavach_ai/backend/pipeline/stage3_ml/normalization.py), [data.py](training/pipeline/data.py)).

### 5.3 Classifier and LoRA

The model is loaded as a two-label sequence classifier. LoRA is attached to the fused query/key/value projection `model.layers.0..21.attn.Wqkv` in all 22 transformer layers:

| LoRA/model setting | Current value |
|---|---|
| Target modules | 22 fused `Wqkv` linear layers (768 → 2,304) |
| Rank / alpha / dropout | 8 / 16 / 0.05 |
| Bias | none |
| Additionally trained/saved | classification `head` and `classifier` |
| Trainable parameters | 1,132,802 of 150,739,204 (about 0.75%) |

Embeddings, MLPs, attention output projections, and base `Wqkv` weights remain frozen. This is a slice-level binary classifier: its intended target is effectively `P(source APK is malicious | normalized sink-centred slice)`, not proof that the slice itself implements malware behaviour ([model.py](training/pipeline/model.py)).

## 6. Current dataset: scope and observed quality problems

### 6.1 APK-level versus slice-level population

| Measure | Benign | Malicious | Total |
|---|---|---|---|
| Unique APKs | 503 | 500 | 1,003 |
| Published slices | 85,048 | 12,837 | 97,885 |
| Mean slices/APK | 169.1 | 25.7 | 97.6 |
| Median slices/APK | 175 | 6 | 69 |
| Zero-sink APKs | 2 | 22 | 24 |
| Partial extraction | 0 | 45 | 45 |
| Failed extraction | 0 | 10 | 10 |

The fixed split contains 702 train, 151 validation, and 150 test APKs. APK-level labels are nearly balanced, but published slice labels are 6.6:1 benign. This is not conventional random-example imbalance: APKs contribute radically different numbers of correlated slices, and benign APKs contribute much more on average.

The serious-run filter excludes internally truncated slices and slices shorter than eight tokens. This leaves 58,970 eligible training slices, of which 7,661 are malicious. The 1:1 policy retains all 7,661 malicious slices and a deterministic cycling sample of 7,661 benign slices per epoch. The alternative uses all eligible slices with balanced class-weighted cross-entropy. Both validate on the natural validation distribution. These policies address label counts, but neither resolves within-APK correlation, weak labels, category imbalance, or shared-code duplication.

### 6.2 Behaviour/category distribution

| Sink category | Published slices | Share | Median tokens | Internally truncated |
|---|---|---|---|---|
| Reflection | 84,121 | 85.94% | 402 | 14.58% |
| Class loader | 10,480 | 10.71% | 595 | 8.18% |
| Native loading | 1,193 | 1.22% | 105 | 8.21% |
| Accessibility | 1,073 | 1.10% | 146 | 0.75% |
| Execution | 689 | 0.70% | 286 | 20.17% |
| SMS | 329 | 0.34% | 1,529 | 42.55% |

> [!warning] Category dominance
> **Reflection contributes 85.94% of published slices.** Aggregate results may therefore measure reflection/library correlations more than the rare behaviours. Category round-robin only affects APKs that reach the 256-slice cap; it does not balance the final corpus.

### 6.3 Weak labels and redundancy

APK labels are copied to every slice:

```text
malicious APK → every selected sink slice labelled malicious
benign APK    → every selected sink slice labelled benign
```

A malicious APK can contain ordinary SDK, compatibility, or benign application code. Its slices are still positive. Conversely, benign uses of sensitive APIs are important negative examples and should not simply be removed. The absence of slice-level ground truth is a central supervision problem.

The corpus audit found 8,258 groups of identical normalized/token content, containing 61,604 duplicate records beyond the first. Of those groups, 5,175 cross the immutable APK splits. Hash-level APK splitting is working as designed, but shared libraries, templates, or repackaged code can therefore appear verbatim in train and validation/test. Current validation metrics can be inflated by code-content leakage even without duplicate APK hashes.

### 6.4 Dataset scope that remains unknown

The current artifacts do not establish:

- malware-family membership or family diversity;
- sample collection source, time range, or label confidence;
- whether benign/malicious samples are matched by age, store, SDK level, or app type;
- the extent of shared third-party libraries or repackaged applications;
- coverage of behaviours absent from the current sink list.

These should be treated as unavailable, not inferred from older proposal/submission documents.

## 7. What the current training outcomes tell us—and do not tell us

Two serious slice-level experiments produced the following supplied validation results:

| Training membership/loss | Accuracy | Malicious precision | Recall | F1 |
|---|---|---|---|---|
| Balanced 1:1, ordinary CE | 83.7% | 37.6% | 76.5% | 0.504 |
| Full natural membership, training-only weighted CE | 91.1% | 99.6% | 18.1% | 0.306 |

The balanced policy gives the more useful recall/F1 trade-off; the weighted model misses most malicious-labelled slices. These are not APK-level metrics and do not reveal whether the model learned behaviour, provenance, category frequency, or duplicated code. Exact run artifacts are absent from this checkout, so the supplied metrics cannot be independently re-derived here; committed configs verify the policies only.

The more informative next step is to test whether classification changes when specific static context is added or removed, rather than begin a larger hyperparameter search.

## 8. Tunable levers

> [!note] Reuse boundary
> Most experiments can reuse `static-ir-v1`; they do not require APKTool extraction. Cost increases from **config/data rebuild**, through **slicer/analysis change**, to **extraction change**.

| Lever | Current setting/behaviour | Change cost | Why tune it |
|---|---|---|---|
| Sink rules/categories | 14 code-defined API rules; six categories | **Config/data rebuild** (small code edit today) | Test missing, noisy, broad, chained, or low-information anchors |
| Call depth | 3 | **Config/data rebuild** | Recover multi-hop flow without excessive expansion |
| Methods per slice | 8 | **Config/data rebuild** | Test whether cross-method context is cut off |
| Candidate callees/callers | 4, deterministic order | **Config/data rebuild** | Reduce arbitrary candidate loss or branching |
| Traversal states | 4,096 | **Config/data rebuild** | Most frequently hit bound; test coverage/cost trade-off |
| Instructions per slice | 256 | **Config/data rebuild** | Low hit rate; verify whether increasing it has value |
| Slices per APK | 256, category round-robin | **Config/data rebuild** | Control APK/category contribution |
| CFG/control dependency | Instruction CFG; reachability-based branch retention | **Slicer/analysis change** | Compare with formal control dependency/PDG variants |
| Virtual/interface dispatch | Recorded as unresolved boundary | **Slicer/analysis change** | Add bounded Android call-graph coverage |
| Field/heap/array model | Field-signature; array-register; no points-to/index sensitivity | **Slicer/analysis change** | Recover dependencies hidden by aliases/heap abstraction |
| Model context length | 1,024 tokens | **Training/evaluation change** | Measure information retained versus compute cost |
| Context policy | Head truncation; no sink-centred window | **Training/evaluation change** after storing sink spans; storing spans requires a **data rebuild** | Preserve anchor/local context reliably |
| Normalization/serialization | Code-defined linear structural-v1 text | **Slicer/analysis change**; IR reused | Test which structure/literals aid learning |
| Per-APK/data sampling | APK-interleaved; balanced or natural/weighted policies | **Training/evaluation change** | Address correlated and unequal APK contributions |
| APK-level aggregation | Not implemented | **Training/evaluation change** | Evaluate the actual APK-level objective and weak labels |

## 9. Proposed validation and improvement work

### Slice-information experiments

Use the same immutable APK membership and compare controlled representations:

```text
sink instruction only
  → sink + fixed local window
  → intraprocedural backward data slice
  → data slice + formal control dependence
  → current bounded interprocedural slice
  → deeper/broader interprocedural variants
```

Measure results per category and APK. Sweep bounds while recording limit hits, size/runtime, sink retention after context truncation, and classification delta.

### Data and evaluation controls

- Deduplicate/group-split identical content and identify common libraries.
- Report category-, APK-weighted, and APK-aggregated metrics.
- Compare APK caps, equal-APK sampling, and APK-interleaved sampling.
- Review stratified TP/FP/FN/TN slices across categories and truncation states.
- Obtain provenance/family labels before held-out or temporal evaluation.
- Store sink token spans and test sink-centred context.

### Possible analysis changes requiring expert input

We have not committed to replacing the CFG/slicer. Candidate changes are captured in the table and review questions; they should be prioritized by likely information gain.

---

## 10. Dynamic analysis and sandbox detonation approach

The dynamic track acts as a live, automated environment manager designed to force code execution and log runtime indicators in under 30 seconds.

### 10.1 Sandbox Architecture & Data Flow
The detonation sequence runs asynchronously via FastAPI. When an APK is uploaded, it is routed to a physical or simulated Android environment where its runtime behaviors are monitored.

```text
                sequence Diagram (Dynamic Sandbox Data Flow)
               
  React Frontend (Vite)         FastAPI Backend       Orchestrator        eBPF & Frida
         │                             │                    │                  │
         ├─── Upload APK (POST) ──────►│                    │                  │
         │                             ├─── start_trace() ──┼─────────────────►│
         │                             │    (eBPF tracker)  │                  │
         │                             ├─── detonate_apk() ─►                  │
         │                             │                    ├─── Install ─────►│
         │                             │                    │    (adb, strip)  │
         │                             │                    ├─── Hook ────────►│
         │                             │                    │    (Frida setup) │
         │                             │                    ├─── Broadcast ───►│
         │                             │                    │    (Intents/Monk)│
         │                             │                    │                  │
         │                             │◄── Stream logs ────┼──────────────────┤
         │                             │    (SSE stream)    │                  │
         │◄── SSE Log/Status Event ────┤                    │                  │
         │                             │◄── Save telemetry ─┼──────────────────┤
         │                             │    (telemetry.json)│                  │
         │◄── SSE Telemetry Result ────┤                    │                  │
```

### 10.2 Technology Stack
The dynamic analysis pipeline integrates several specialized security and systems-level tools:
- **FastAPI (Python 3)**: Processes incoming multipart uploads, runs sub-processes asynchronously, and streams logs to the frontend via Server-Sent Events (SSE / EventSource).
- **Android Debug Bridge (ADB)**: Deploys the package on connected emulators, launches activities, and broadcasts intents.
- **Frida**: Instruments the app process at startup, overriding key checks in the Dalvik/ART runtime.
- **eBPF (Extended Berkeley Packet Filter)**: Hooks Linux syscalls (`sys_clone`, `sys_connect`, `sys_openat`) invisibly in the host emulator kernel.

### 10.3 Signature and ABI Adaptations (Fault-Tolerant Installation)
To bypass emulator installation errors, Kavach implements a three-attempt loop:
- **Resigning Signature Checks**: Strips original certs (`META-INF/` signature files) and signs the APK using a debug keystore via JDK `keytool` and `jarsigner` to bypass `INSTALL_PARSE_FAILED_NO_CERTIFICATES`.
- **ABI Mismatch Workaround**: Strips the native library (`lib/`) directory from the ZIP workspace, removing compiled C/C++ libraries. This forces the Dalvik execution environment to run the bytecode natively, bypassing `INSTALL_FAILED_NO_MATCHING_ABIS` checks.

### 10.4 Dynamic Privilege Auto-Elevation
- **Overlay Permissions**: Grants the `SYSTEM_ALERT_WINDOW` permission programmatically using `adb shell appops set <package> SYSTEM_ALERT_WINDOW allow` to prevent permission UI blocks.
- **Device Administrator Bypass**: Auto-activates receivers registered to `android.app.action.DEVICE_ADMIN_ENABLED` via `adb shell dpm set-active-admin --user current <receiver_name>`.
- **Accessibility Integration**: Enables service profiles directly by updating secure system settings via ADB (`settings put secure enabled_accessibility_services <service_id>`).
- **Legacy Warning Dismissal**: Simulates keyevents (DPAD_CENTER `66`) to automatically click through overlay warning popups.

### 10.5 Frida Hooking Stability Rules
We override anti-sandboxing controls (anti-root checks and SSL Pinning) while maintaining target process stability:
- **Thread-Local Re-entrancy Guards**: Uses boxed Java `ThreadLocal` variables (e.g. `java.lang.Boolean`) to prevent stack trace deadlocks within high-frequency filesystem read/write hooks (`FileInputStream`/`FileOutputStream`).
- **Safety Boxing & Type Verification**: Bypasses local/IPC cast errors in `Socket.connect` by verifying address arguments using `InetSocketAddress.class.isInstance(endpoint)`.
- **Hook Mappings**:
  - Intercepts and redirects `java.io.File.exists` queries on `su` or `Superuser` binaries.
  - Redirects `java.lang.Runtime.exec` commands targeting terminal shell flags, throwing fake IOExceptions to simulate non-rooted ROMs.
  - Intercepts OkHttp3 pinning `okhttp3.CertificatePinner.check` and overrides `SSLContext.init` to bypass certificate verification dynamically, allowing proxy interception.

### 10.6 eBPF Kernel Stealth Observers
To bypass user-space sandbox detection checks, Kavach supports pre-loading bpftrace probes inside the emulator kernel:
- Hooks `sys_enter_connect`, `sys_enter_openat`, and `sys_enter_execve`.
- Logs file edits and dynamic socket operations in a stealthy kernel channel, ignoring user-land integrity monitors.

### 10.7 Dynamic Threat Score Formulation
The dynamic risk score (`probability`) is computed at runtime based on the telemetry parameters:
- **Base Score**: Starts at `0.05` (5%).
- **Frida Hook Triggers**: Adds `0.35` if Root bypass hooks were triggered (`objection_root_bypass`) and `0.30` if SSL bypasses occurred (`objection_ssl_pinning_bypass`).
- **File I/O Signals**: System path reads (e.g., `app_process`, `/system`) increase the threat score by `0.25` each. Internal config/preference directory reads add `0.15` each.
- **Network Vectors**: Socket connections on reverse-shell ports (such as `4444`) increase the score by `0.45`. Other standard connection requests add `0.10`.

---

## 11. Backend Infrastructure & Relational Data Model

To prevent the user interface from blocking during heavy ML calculations or sandbox detonations, Kavach.ai runs on a decoupled server model.

### 11.1 FastAPI Asynchronous Non-Blocking Flow ("Restaurant Ticket" Paradigm)
When an APK is uploaded, the FastAPI backend does not block:
1. **Ingest**: FastAPI accepts the uploaded file.
2. **Vault**: Vaults the physical binary file to the database.
3. **Ticket Generation**: Records a transaction row in PostgreSQL, returning a unique `Job ID` (receipt ticket) instantly to the client.
4. **Background Handoff**: Dispatches the analysis tasks to background worker processes, freeing FastAPI to ingest concurrent requests.
5. **Client-Side Polling**: The client uses the `Job ID` to poll the status endpoint (`GET /api/jobs/{id}`) every 2 seconds until the state transitions to `Completed`.

### 11.2 Relational Domain Separation (SQLModel & BCNF)
The SQLModel schema maps database properties into Boyce-Codd Normal Form (BCNF) separated into three relational domains to enforce data integrity:
1. **The Artifact Domain (`apks`)**: Tracks uploaded binaries, hashes (SHA-256), filenames, and upload timestamps.
2. **The Execution Domain (`smali_slices` & `shap_attributions`)**: Represents the state machine. Stores intermediate decompiled code slices and token attributions, mapping them to the Artifact Domain via Foreign Keys.
3. **The Intelligence Domain (`cert_in_reports`)**: Stores final structured findings (MITRE ATT&CK codes, PDF compliance reports).

---

## 12. Unified Project Directory Structure

```
kavach_ai/
├── .env                        # Environment variables (Database credentials, API keys)
├── pyproject.toml              # Modern Python dependency management (uv/poetry)
│
├── infrastructure/             # DevOps & Local Environment
│   └── docker-compose.yml      # Spins up PostgreSQL & Redis containers natively
│
├── frontend/                   # Vite + React + TypeScript Dashboard
│   ├── package.json            # React project dependencies
│   ├── vite.config.ts          # Build orchestrator configuration
│   ├── index.html              # Core DOM entry template
│   └── src/                    # Component implementation
│       ├── main.tsx            # React application bootstrapper
│       ├── App.tsx             # Root component router
│       ├── index.css           # Global layout & utility tokens
│       └── components/         # Interactive UI components
│           ├── app-shell.tsx   # Dashboard layout framework
│           ├── dashboard.tsx   # Aggregated status center
│           ├── kavach-scorecard.tsx # Redesigned left-bordered threat scorecard
│           ├── static-view.tsx # Bytecode triage & manifest metrics view
│           └── views/
│               └── kavach-report-view.tsx # Two-page Space Grotesk A4 generator
│
└── backend/                    # The FastAPI Orchestrator & Workers
    ├── app/                    # Web Server Layer (Traffic Controller)
    │   ├── main.py             # FastAPI entrypoint
    │   ├── db/                 # SQLModel layer (session.py, models.py)
    │   └── api/                # HTTP Endpoints (routes.py - handles /upload & /status)
    │
    ├── pipeline/               # The Proprietary Kavach.ai Brain (Isolated)
    │   ├── stage1_triage/      # Manifest parsing & 10ms permission filter
    │   ├── stage2_static/      # Androguard CFG & Smali fallback extraction
    │   ├── stage3_ml/          # SecureBERT-2.0 PyTorch local inference logic
    │   ├── stage4_dynamic/     # Frida hooks, dynamic resignation & ADB triggers
    │   ├── stage5_explain/     # PartitionSHAP / FastSHAP attributions
    │   └── stage6_synthesis/   # Telemetry merge & LLaMA-3 JSON formatting
    │
    └── workers/                # Background Task Queue (Redis Broker)
        └── arq_worker.py       # Celery/ARQ task runner
```

---

## Questions for Review

1. Is suspicious-sink-centred backward slicing a sound primary representation for malicious-versus-legitimate API use? How should we refine the sink catalogue, and what baseline should it be compared against?
2. Does the current register/field/array use-def model plus reachability-based control retention preserve sufficient context? Which improvement—heap/alias precision, array precision, implicit flow, or formal control dependence—is most likely to matter?
3. Which Android-specific edges and interprocedural mechanisms—lifecycle, callbacks, ICC, asynchronous work, framework calls, or bounded virtual/interface dispatch—are essential without causing unmanageable expansion?
4. How should unresolved reflection and dynamic loading be represented, given that reflection supplies 85.94% of current slices?
5. Are the current limits (depth 3, 8 methods, 4 candidates, 4,096 states) reasonable, and what empirical calibration protocol would you trust?
6. What annotation, measurement, or ablation would establish that a slice contains sufficient semantics without requiring whole-APK reverse engineering?
7. How should APK-level labels supervise slices that lack individual ground truth—APK aggregation, multiple-instance learning, positive-unlabelled learning, attention over slices, or another formulation?
8. How should APK/category contribution, duplicate/shared-library content, provenance, and family-held-out splitting be controlled while retaining legitimate benign counterexamples?
9. Should manifest, native/JNI, and other APK-level evidence be included in slice representations or fused only during APK-level aggregation?
10. **Given the implementation, observed limit-hit rates, dataset characteristics, and limited development time, which 2–3 changes or experiments would you prioritize first to maximize useful behavioural information per slice without excessive path/context explosion?**
11. **How can we best synchronize Frida instrumentation hooks during virtual machine setup to catch early-stage evasive checks (such as anti-emulation triggers or dynamic class decryptors) without causing Dalvik execution overhead or JVM pointer crashes?**
12. **For our eBPF stealth execution monitor, what configuration patterns do you recommend to reliably log system-level anomalies (such as direct syscalls bypassing libc/binder) within the emulator kernel, and how can we map these low-level streams back to the corresponding higher-level Java method invocations?**
13. **Android applications often employ multi-threading, handlers, and asynchronous Task executors. What strategies are most effective to prevent our runtime call-graphs and dynamic flow paths from breaking at these asynchronous dispatch boundaries?**
14. **When bypass hooks fail and crash the application runtime, what automated rollback or secondary instrumentation policies should be implemented to ensure we salvage intermediate telemetry data?**
15. **Should dynamic telemetry metrics be fed into the SecureBERT LoRA model as combined text sequence features, or is it better to merge static code probabilities and dynamic system traces at a later synthesis aggregation layer?**
