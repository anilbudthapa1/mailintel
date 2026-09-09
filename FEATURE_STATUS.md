# v1.4 implementation status

This version delivers a consolidated email-only toolkit. It is not full completion
of every capability discussed in the proposed v1.1–v1.4 roadmap. The table below is
the acceptance record: a CLI command is evidence of implementation, not evidence
that a commercial account or live upstream service has been tested.

| Roadmap capability | Implementation / remaining limits |
|---|---|
| Company email discovery | Hunter search and optional theHarvester; source records retained; not all screenshot sites |
| Email patterns and guesses | `patterns` CSV requires known first/last names; `candidates` labels all guesses |
| Account associations | Opt-in GHunt/Holehe external runners; installations, login and live validation remain external |
| Deliverability | Hunter verifier adapter; no native Reacher runner or local SMTP probing |
| Breach/reputation | Existing HIBP/EmailRep; source-labelled imported claims; no other native paid adapters |
| Disposable detection | Bundled dataset with provenance; updates manual, not automatic |
| Mail blacklists | `blocklist` raw IPv4 DNSBL response; zone interpretation manual |
| Header analysis | `mailbox` includes recorded authentication headers; claims not blindly trusted |
| Merge and compare | Address normalization, source references, structural run comparison; no owner identity merging |
| Batch | Bounded syntax/disposable/DNS batches; paid batching not enabled; per-provider rolling request budgets and user-estimated cost accounting available |
| Relationship graph | Static SVG connects domains, HIBP breach claims, imported account claims and positive Holehe results with evidence references; no interactive graph editor |
| Confidence | Explicit observed/claimed/heuristic/guess labels; not a numeric confidence engine |
| Historical discovery | `archive` collects up to three snapshots of one explicit page; no whole-site/archive crawling |
| Document extraction | TXT/HTML/CSV and DOCX; PDF via bundled pypdf; no OCR |
| Lookalike detection | Local typo candidates; no full Unicode confusable dataset or registration sweep |
| PGP | Published armored public-key lookup; no local fingerprint/ownership verification |
| Alias hints | Gmail-specific hints; never merge originals; other providers remain unchanged |
| Authentication | DNS records, bounded SPF include/redirect traversal, MX destination checks; PSL-based DMARC fallback and MTA-STS policy collection; not full sender-policy evaluation |
| DMARC reports | Bounded plain XML import, counts and policy-result fields; no compressed input |
| Watch alerts | Persistent offline/DNS jobs invoked by cron; changed/failed results printed as JSON; no email/SMS push |
| Provider health | Key presence, most recent status and dataset metadata; rolling local reservations and estimated costs; no provider-confirmed paid quota/expiry validation |
| Evidence bundle | Stored run hashes, reports, insights and environment versions; original files remain separate |
| Mailbox search | Local EML/MBOX, up to 25 MiB / 1000 messages, text query |
| Threads | Message-ID parent edges, missing-parent hints; no heuristic subject-based reconstruction |
| Diversion | Reply-To and labelled payment-detail changes within parent-linked messages; heuristic review only |
| Tracking/link inspection | Hidden/small images, link destination/display mismatch, query markers; no link fetching |
| Attachment inventory | Names, declared types, selected magic signatures, SHA256; not exhaustive file identification or malware verdict |
| DKIM | Bundled dkimpy current-DNS first-signature verification; historical keys not reconstructed |
| Infrastructure comparison | Shared from/by Received tokens; untrusted header evidence, no owner attribution |
| Exposure locations | Supplied document line/page and context; no unrestricted web/code crawling |
| Conflict review | Conflicting imported values retained; reviewer decisions are append-only case runs |
| Completeness | Failures, conflicts, evidence presence and review events; not a guarantee of investigation coverage |
| Redaction | Email pseudonyms, body/payment removal, user-specified exact secret terms; manual final review still needed |
| Removal tracking | Manual append-only status/source/note log; no outreach or automated deletion requests |
| Domain lifecycle | RDAP bootstrap link and generic dated claim import; full registry history/expiry monitoring not implemented |
| Dangling mail configuration | MX destinations missing both A and AAAA flagged; claimability is NOT tested |
| Contact publication timeline | Dated claims plus archive snapshot appearance changes; no proof of employment changes/removal |
| Role addresses | Common-role heuristic; no user-configurable role vocabulary yet |
| Source independence | Groups identical declared upstream sources; does not discover hidden syndication |
| Second analyst review | Named review log, original evidence preserved; no login, roles or enforced approvals |
| Synthetic training | Included fictional messages, claims, contacts, DMARC report and expected-results guide |

No claim of OSCP exam approval. Local data and evidence exports are private by
filesystem permissions but NOT encrypted. No authenticated multi-user service.
