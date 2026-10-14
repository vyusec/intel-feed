# Review and corrections

Zoli-generated static, metadata and runtime signals always require approval. A reviewer must inspect the exact artifact hash and affected version, examine the referenced evidence, and choose `malicious` only when malicious behavior is supported. Otherwise publish a justified `suspicious` warning or reject the finding.

Record the reviewer identity and a concrete rationale. API review requests require the inspected revision, preventing a stale decision from approving newly changed evidence. Upstream corrections and runtime evidence can invalidate previous review and require another decision.

Static rules intentionally identify combinations of capabilities. Network use, obfuscation, naming similarity and install scripts are not individually malware verdicts. Runtime traces include installation tooling as well as package behavior; process execution alone is expected. Separate environmental and installation failures from observed package behavior.

Original upstream reports are stored privately by SHA-256. Operators can retrieve them through `GET /admin/raw/{source_revision_hash}`. Static artifacts and analysis JSON are retained in the private artifact store. Complete runtime traces and runner configuration are retained on the isolated host under its `storage_dir/traces`, identified by the reported trace SHA-256.

Public evidence must omit credentials, personal information, unrelated filesystem paths, raw process arguments and complete malware archives. Review references before publication. Community issue bodies and pull requests are untrusted input; no workflow automatically executes submissions or publishes their verdicts.

Maintainers can request correction through a threat-report issue with the finding ID, disputed package versions, evidence and references. Review the request, preserve the audit trail, and issue a corrected record or withdrawal. Published withdrawals propagate through signed deltas and hosted queries. Keep attribution to the original source even when its claim is later withdrawn.

Original contributions are Apache-2.0 for code/rules and CC-BY-4.0 for original intelligence. Contributors must identify third-party evidence and its license rather than assigning Zoli's license to it.
