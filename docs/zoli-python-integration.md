# Zoli Python integration handoff

Phase 3 development resumed on 30 October 2026 at the user's request. Zoli's initial Python slice uses the existing signed feed schema and cached query contract; no feed endpoint or database migration is introduced.

## Identity and outcome contract

The client normalizes PyPI package names by lowercasing and collapsing runs of `-`, `_` and `.` to `-`. The public registry identity is `https://pypi.org`; `/simple/` normalizes to it. Private registry identities remain distinct.

Zoli now accepts `check --eco PyPI --name <name> --ver <exact-version>`, optionally with `--sha256 <artifact-digest>`. The first matcher supports concrete version comparison, exact affected versions and OSV event ranges. PyPI constraint-string ranges and malformed event boundaries refuse in Rust until parity is implemented. This is feed-only assessment, not guarded pip installation or local Python artifact inspection.

Preserve the three query states (`known_match`, `no_known_match`, `insufficient_information`), certainty, coverage and freshness. Missing artifact hashes preserve uncertainty for hash-scoped findings. A different artifact digest may exclude a hash-scoped report but cannot erase a package/version-wide finding. A withdrawn report no longer contributes a match. Zoli blocks malicious findings even when uncertain, requires declared PyPI coverage, and applies the existing source/publication freshness and CI suspicion rules.

## Executed local compatibility evidence

The Zoli generator copies and inventories this Go source, then executes `model.Compare` and `api.QueryAt` in a development-only overlay. Its seventh fixture family contains **6,084 concrete PyPI comparison/error cases**. Fifteen new exact-response query cases cover normalization, equivalent versions, prereleases, fixed/last-affected ranges, epochs, local labels, hashes, private registries, withdrawals and stale sources. The total query corpus is now 51 cases.

Rust matching follows the actual pinned Go implementation, including existing comparison limits and quirks. These finite fixtures do not establish full pip resolver or arbitrary PEP 440 constraint parity. Source provenance and generated fixtures live in the sibling Zoli workspace under `testdata/conformance/`.

The feed service code was unchanged in this kickoff, so its database/race/container suites were not repeated. Heavy oracle/Rust checks use a 50%-of-one-core cgroup cap, one build/test worker and low scheduling priority. Existing deployment, healthy ingestion and live hosted/client acceptance gates remain open in [foundations](foundations.md).

## Next gates

Extend the constraint oracle before exposing constraint matching in Rust. Then validate wheel acquisition, artifact identity/integrity, bounded inspection and dependency completeness before enabling pip. Real installation and relisting/cache bypass tests remain distinct from these feed-query fixtures. Runtime analysis stays disabled unless separately authorized and validated.
