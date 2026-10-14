# Rule catalog

Static rules live in `rules.yaml`; changing their patterns or evidence requirements requires a version bump and regression evaluation. The initial rules find signals in one file and do not establish cross-file executed data flow.

| Rule | Version | Behavior | Required evidence |
|---|---|---|---|
| ZOLI-STATIC-001 | 1.0.0 | Credential-path/token references with network submission | Both pattern groups in the same npm/Python source file |
| ZOLI-STATIC-002 | 1.0.0 | Remote download with process execution | Both pattern groups in the same matching source or manifest file |
| ZOLI-STATIC-003 | 1.0.0 | Decoding with dynamic execution | Both pattern groups in the same source file |
| ZOLI-META-001 | 1.0.0 | Name resembles a protected package | One insertion, deletion or substitution against configured protected names; queue priority signal |
| ZOLI-META-002 | 1.0.0 | Installation hook present | `preinstall`, `install` or `postinstall` in the archive's root package manifest |
| ZOLI-RUNTIME-001 | 1.0.0 | Runtime capabilities observed | Host-side gVisor telemetry records credential-path reads, network attempts or process execution |

Metadata and runtime rule implementations are versioned in `internal/discovery` and `internal/analysis`; their configuration is part of reproduction. They produce review evidence, never automatic malware verdicts.

The current synthetic evaluation includes a documentation lookalike that is intentionally counted as a false positive. Do not remove difficult benign examples to improve reported scores. Keep held-out cases separate from fixtures used to tune a rule, publish mistakes, and add independently labeled real samples before reporting real-world precision or recall.
