# Feed format 1.0

The hosted feed is a transport-independent set of immutable files and one publication pointer. The API and feed files use the same committed publication, so unpublished review changes do not alter public query results.

`GET /feed/latest.json` returns:

```json
{
  "manifest": {"schema_version":"1.0","sequence":42,"generated_at":"...","record_count":100,"records_sha256":"...","files":[],"sources":[],"coverage":[]},
  "key_id":"...",
  "signature":"base64 Ed25519 signature"
}
```

The example omits fields for readability. `signature` covers the exact compact JSON bytes inside `manifest`. Verify using a public key distributed with Zoli, never a key supplied by an untrusted manifest. `key_id` is the first 16 hex characters of SHA-256 of that public key. Clients persist their latest sequence and reject older publications; gaps in sequence numbers are allowed after interrupted publication.

Every file descriptor supplies `path`, `kind`, `sha256`, compressed `bytes`, and creation time. Snapshot files also specify an optional ecosystem; delta files specify `from_sequence` and `to_sequence`. Paths are relative to the `/feed` base. Verify the compressed bytes before decoding gzip or JSONL.

Each JSONL snapshot row is a record. `records_sha256` authenticates the full ordered record set after delta application: sort by record ID, encode each record with Go's JSON field order and HTML escaping disabled, append a newline after every row, then hash those bytes. The supplied Go client implements this rule. Other-language clients can alternatively fetch and verify the full signed snapshot, retaining its original uncompressed bytes to avoid reserialization differences.

Delta rows contain `operation`, `id`, and an optional complete `record`. Operations are `upsert`, `withdraw`, and `remove`. A withdrawal row preserves the report and its history but disables the finding. Apply only a chain beginning at the client's current sequence. If a chain is unavailable, use a full snapshot. Persist the new cache only after verifying its record count and record hash.

Affected package identities contain ecosystem, name, registry and optional version, SHA-256, Conda channel, subdirectory and build. An explicit `versions` list and supported ranges can select affected versions. `scope: all` must be an explicit assertion; an absent version scope is `unknown`. Git commit ranges and Conda version ranges are retained but return uncertainty. Registry names are not interchangeable, and PyPI findings are never transferred to Conda by name alone.

Records retain source IDs, aliases, licenses, URLs, source revisions and retrieval timestamps. Deduplication requires an explicit shared alias and identical affected scope/classification/status. Duplicate imports are not evidence of independent corroboration. Different scopes remain separate findings.

`published` records are active. `withdrawn` records are tombstones. Pending and rejected private findings do not appear publicly. Source errors and freshness timestamps are signed; clients must surface degraded or stale intelligence without calling a package safe.

Schema changes require client compatibility review. Key rotation requires distributing the next verification key through a trusted channel before switching signing keys.
