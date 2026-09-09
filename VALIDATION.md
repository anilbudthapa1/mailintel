# Validation — MailIntel 1.4.0

Environment: Linux, Python 3.12.14. Other distributions and Python versions are
not tested here. Pure-Python dependencies are bundled for Python 3.10+.

41 tests pass, with no skips in this environment:
- Existing normalization, offline enforcement, provider errors/cooldowns, data
  provenance, scoped theHarvester import, report escaping and evidence integrity.
- Message parsing, links, pixel hints, attachment signatures, thread relationships
  and labelled payment-detail changes using fictional messages.
- Text/PDF extraction, alias hints, DMARC XML, UTF-8/UTF-16 entity rejection.
- Claims/conflicts/shared sources, redaction, comparisons, review boundaries,
  evidence bundles, graph export and prevalidation of batch inputs.
- Hunter header authentication, redirect refusal, local budgets and watch scheduling
  with mocked network or socket blocking.
- Archive snapshot comparisons and PSL/DMARC fallback/MTA-STS parsing using mocked
  transport/DNS. No live target or real-person queries are part of these tests.
- RSA DKIM: openssl generates a disposable test key; dkimpy signs a fictional
  message; verification succeeds and a modified body fails, using mocked key DNS.
- GHunt invocation tested against a fixture executable, not live GHunt.

Fresh core installation uses --no-index and --require-hashes. The demo creates a
case, imports fictional evidence, and exports HTML, graph, redacted copy and ZIP.

External limits: no live paid HIBP/Hunter/EmailRep accounts were available. PGP,
archive and registry collection are not end-to-end verified against live services.
GHunt/Holehe/theHarvester real installations/login/provider responses remain
untested. Live DNS in this environment was unavailable in the earlier baseline
smoke check; new DNS/authentication behavior is tested with controlled fixtures.
No independent security audit, adversarial parser fuzzing or performance benchmark
has been performed. Inputs are bounded but this is not a hardened malware sandbox.

The package version is 1.4.0; FEATURE_STATUS.md explicitly records partial and
unimplemented roadmap items. It is not a claim of full roadmap completion or
OffSec exam approval. File hashes are consistency checks, not publisher signatures.

Final clean-copy check: installed the bundled wheel in a new virtual environment
with all package indexes disabled; all 41 tests passed against the installed
package from outside the source directory. The offline demo exported and hash-
verified six runs. Representative fictional report and graph are included.
