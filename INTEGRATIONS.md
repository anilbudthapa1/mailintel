# External integrations

MailIntel never enables paid or account-association queries merely because keys exist.
`lookup`, `accounts`, `harvest`, `auth`, `dkim`, `blocklist` and passive scans explicitly
make network requests. Mailbox/document imports and offline scans do not.

| Integration | Setup | Verification in this build |
|---|---|---|
| HIBP | HIBP_API_KEY | Mock API tests; live paid account not tested |
| EmailRep | EMAILREP_API_KEY if required by your account | Mock API tests; live account not tested |
| Hunter search/verifier | HUNTER_API_KEY | Header-auth mock test; live account not tested |
| Public PGP lookup | No key; keys.openpgp.org | Adapter implemented; live lookup untested |
| RDAP bootstrap | No key; rdap.org | Redirect is recorded, not followed; normally returns registry URL for manual use |
| theHarvester | Separate upstream installation | Existing runner tested with fake executable; live tool untested |
| GHunt | Separate installation and upstream login | CLI argument shape inspected in source; live tool untested |
| Holehe | Separate installation | CLI argument shape inspected in source; live tool untested |
| DNSBL | Supply a zone you are entitled to query | Raw DNS response only; zone-specific error/listing interpretation is manual |

Reviewed GHunt revision: 5ee893929c51c7a8a665b199bbae04ce85a662b4
https://github.com/mxrch/GHunt
Reviewed Holehe revision: 14da70f588538936b20d238783c5e28a0772a2b3
https://github.com/megadose/holehe
These tools are NOT redistributed. To install separately, with uv available:

```bash
uv tool install 'git+https://github.com/mxrch/GHunt.git@5ee893929c51c7a8a665b199bbae04ce85a662b4'
uv tool install 'git+https://github.com/megadose/holehe.git@14da70f588538936b20d238783c5e28a0772a2b3'
```

Follow GHunt's upstream login instructions. The runners inherit upstream credential
locations from your environment; MailIntel API keys are removed from their environment.
They suppress console output and terminate the process group after 180 seconds.
Holehe uses its `--no-password-recovery` option, but modules still interact with
third-party endpoints: the wrapper cannot guarantee that an upstream service never
sends notifications. A changed upstream output schema may require adapter updates.

Reacher, OSINT Industries, DeHashed, Hudson Rock, commercial people-search sites,
and other screenshot sources are NOT direct native integrations. Use `import-claims`
for your lawfully obtained results with explicit provenance. This is a documented
exchange format, not automatic compatibility with those providers' exports.
There is no scraping of login walls or circumvention of API subscriptions.

Primary API documentation inspected for new adapters:
- https://hunter.io/api-documentation/v2 (header authentication, search and verification)
- https://keys.openpgp.org/about/api/ (email lookup)
- https://about.rdap.org/ (bootstrap redirect)

Hunter verification may cause active SMTP checks at the provider. Account and
breach results do not prove identity. No passwords are requested from breach APIs.
Do not substitute provider availability or HTTP errors for a negative finding.
