# Feed readiness roadmap

Baseline: 16 October 2026 (Asia/Kolkata). [Progress](progress.md) records capability status; [validation](validation.md) records what was actually exercised.

Update: 30 October 2026. The local database gate is now exercised without skips, static workers have atomic lease-fenced completion, and the controlled review/publication lifecycle passes. Phase 1 healthy live-source acceptance and Phase 2 deployed discovery/worker acceptance remain open. Following that local pass, the user authorized starting Phase 3 integration development on 30 October; see the [acceptance matrix](foundations.md).

## Phases and exit gates

| Phase | Deliverable | Exit gate | Current state |
| --- | --- | --- | --- |
| 0 — Baseline | Evidence-backed progress, roadmap and validation instructions linked from README | Implemented, validated and blocked work are distinguishable | Complete; dated evidence, blockers and reproduction instructions recorded |
| 1 — Ingestion and signed delivery | Dedicated database validation, configured source bootstrap/replay, signed publication and verified client consumption | Database tests execute without skips; each configured source completes; verified hosted/local lookups agree; correction and withdrawal updates propagate | Active: local parser/checkpoint/withdrawal repairs and complete archive replay pass; local database gate passed 30 October; healthy deployed backfill/replay pending |
| 2 — Static analysis | Controlled npm/PyPI artifacts through discovery, queue, analysis and review | Only approved findings publish; leases, retries, skips, budgets and coverage gaps are observed | Started: one-minute polling, protected-package recovery, exact-version queue tests and continuous worker overlay prepared; controlled PostgreSQL worker/review lifecycle passed 30 October; live acceptance pending |
| 3 — Zoli integration | Client configuration and examples for identity, trust, cache, query outcomes, freshness and withdrawals | Zoli consumes verified intelligence and explicitly handles uncertainty/staleness | Active: normalized PyPI exact/event/hash queries now have Go→Rust oracle evidence; existing degraded-feed transport evidence retained; healthy live agreement pending |
| 4 — Staging operations | HTTPS, persistent volumes, scheduled work, monitoring and restore | Successful restart and restore preserve history, checkpoints, signatures and publication sequence; scheduled cycles remain healthy | Deployment recipes present; operation unverified |
| 5 — Runtime analysis | Separate disposable gVisor host and digest-pinned analysis images | Controlled fixtures prove isolation, telemetry, time/memory/process limits and inconclusive-result behavior | Disabled; host validation pending |

Run Phase 1 before using feed results for installation policy. Phase 3 integration development has resumed at the user’s request; remaining Phase 1/2 live acceptance gates still apply to readiness claims. Existing cross-language conformance is a foundation regression gate. Staging acceptance includes Phases 1–3. Runtime execution is a later capability and is not required for the initial report feed.

## Initial readiness run — 16 October 2026

Allow about six hours excluding upstream bootstrap delays. Stop a dependent gate when its prerequisites fail, record the exact failure, and prepare its next command for an environment that meets the prerequisites.

| Order | Time budget | Action | Completion evidence |
| --- | --- | --- | --- |
| 1 | 45 min | Save progress, roadmap and a reproducible validation runbook | Linked docs with dated baseline and explicit pending gates |
| 2 | 90 min | Build; run race tests, vet, offline npm-lock checks and synthetic evaluation; include a dedicated PostgreSQL database | Command results, environment/tool versions and database test names with no skips |
| 3 | 90 min | Run isolated report-only source backfills, publish, then replay incremental ingestion | Source success timestamps, counts, checkpoints, errors and stable report revisions on unchanged replay |
| 4 | 90 min | Verify a client update over trusted HTTPS, cache save/reload and hosted/local agreement; use a separate synthetic feed for approval/correction/withdrawal | Publication sequences, verified hashes and lookup/update results; fixtures excluded from the real source feed |
| 5 | 45 min | Record results and unresolved gates | Updated progress and validation evidence, with the next executable action |

Local runtime execution stays disabled. Use development keys and isolated storage for readiness work; do not publish controlled fixtures to a production feed.

16 October result: the documentation and offline foundation were complete. The race run passed 32 top-level Go tests, with four database tests skipped; a targeted database retry confirmed the socket restriction. Three npm-lock checks and the limited PostgreSQL standalone checks passed. Client regressions and a runnable HTTPS comparison command closed the offline preparation work. Live ingestion, service operation and HTTPS delivery remained pending for that environment. See the 22 October update above for subsequent evidence and remaining gates.

The next action is [the dedicated database gate](validation.md#complete-the-database-gate) on a socket-capable host, followed by the documented report-only ingestion and isolated synthetic client lifecycle. Neither external service publication nor runtime-host activation was performed during this pass.

## Required scenarios

- Database lifecycle: approval and unchanged replay, stale-review rejection, publication, correction/withdrawal, private replacement isolation, source checkpoint preservation after partial failure, job leases and budgets.
- Delivery: verified full snapshot, cache save/reload, hosted/local lookup agreement, incremental updates and unchanged-manifest behavior.
- Trust: reject tampered manifest/artifact/cache content and rollback; fall back to a full snapshot when a delta chain is missing.
- Consumer semantics: exact/range/uncertain matches, absent versions, report-only coverage, incomplete or stale sources and all three query statuses.

Use existing tests where they cover a scenario. Add focused regression coverage only for a concrete missing acceptance check or a discovered failure. In-memory fixture results must not be counted as live ingestion or deployed-service validation.

## Next acceptance work

1. Clear any Phase 1 environment blockers and capture database/live-delivery evidence before marking the feed ready for Zoli integration.
2. Exercise controlled static workers and review under Phase 2; independently label more samples before making detection-quality claims.
3. Integrate the verified feed into Zoli using [the handoff contract](progress.md#zoli-handoff-contract), then agree on installation behavior in the client project.
4. Complete staging monitoring/restart/restore and then controlled runtime-host validation.

No API or feed schema change is required by this roadmap. Update the roadmap when a phase passes; attach evidence rather than inferring completion from code or a workflow definition.
