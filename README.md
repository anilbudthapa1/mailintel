# MailIntel 1.4.0

**An email-only OSINT and evidence-analysis toolkit for Linux.**

Linux CLI and terminal menu. Local email/mailbox analysis, public-source adapters,
case evidence, graph exports, reviews and training. Source code is included.
**Read FEATURE_STATUS.md:** this consolidated build does not claim every proposed
roadmap feature or every screenshot website is fully integrated. Live commercial
services and separately installed upstream tools have not been end-to-end verified.

## Purpose and benefits

MailIntel brings email investigation tasks into one local case workspace. It helps
students practise on fictional evidence and helps analysts organise email-related
findings during authorised assessments and suspicious-message investigations.

1. **Understand suspicious email:** inspect headers, actual link destinations,
   possible tracking images and attachment metadata without opening remote content.
2. **Research addresses and domains:** combine local checks with explicitly chosen
   discovery, breach, reputation and public-source services.
3. **Keep evidence organised:** each saved analysis has a case ID, run ID, time and
   integrity hash. Reports preserve observations and their limitations.
4. **Explain conclusions:** distinguish syntax, published occurrences, provider
   claims and guesses; compare conflicting sources rather than assume ownership.
5. **Work offline when possible:** document/mailbox analysis, disposable-list checks,
   reports and training do not need provider accounts.
6. **Share reviewable work:** produce HTML/JSON, graphs and evidence ZIPs, with a
   separate redaction workflow for copies you intend to share.
7. **Maintain a portfolio project:** publish the source, tests, documentation and
   fictional training examples to GitHub using the included release script.

This is not a general network exploitation toolkit. A valid email format, published
key, associated account or deliverability result does not establish who owns an
address. See [FEATURE_STATUS.md](FEATURE_STATUS.md) for the exact implementation
status and [INTEGRATIONS.md](INTEGRATIONS.md) for external-service requirements.

## Quick navigation

- [Installation and first run](#start)
- [Create a case](#create-a-case)
- [Numbered feature and command reference](#numbered-feature-and-command-reference)
- [Provider keys and upstream tools](#provider-keys-and-upstream-tools)
- [Upload this version to GitHub](#upload-this-version-to-github)
- [Troubleshooting](#troubleshooting)

## Start

Python 3.10+ with venv support is required. On Kali/Parrot/Ubuntu, if missing:

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv unzip
```

Extract the ZIP into a permanent directory, then:

```bash
cd mailintel-v1.4
bash install.sh
bash demo.sh
bash menu.sh
```

Core dependencies are bundled, hash pinned, and installed without a package index.
The installer creates `.venv` and a user launcher only when its path is unused.
Use `bash run.sh` if an older `mailintel` launcher exists. Keep this directory in
place. Set `MAILINTEL_NO_LAUNCHER=1` during installation to skip creating a launcher.
No root is needed for MailIntel itself. Optional upstream installations need internet.

## Create a case

```bash
CASE_ID=$(./run.sh case new --name 'My email investigation')
./run.sh scan email 'student@example.com' --case "$CASE_ID" --profile offline
./run.sh mailbox examples/training.mbox --case "$CASE_ID"
./run.sh extract examples/contacts.txt --case "$CASE_ID"
./run.sh dmarc examples/dmarc.xml --case "$CASE_ID"
./run.sh candidates --first Alice --last Smith --domain example.com --case "$CASE_ID"
./run.sh patterns examples/names.csv --case "$CASE_ID"
./run.sh lookalikes example.com --case "$CASE_ID"
./run.sh batch examples/emails.txt --case "$CASE_ID"
./run.sh insights --case "$CASE_ID"
./run.sh report --case "$CASE_ID" --out ./report-1
./run.sh graph --case "$CASE_ID" --out ./graph-1
./run.sh bundle --case "$CASE_ID" --out ./evidence-1.zip
```

HTML reports and graphs work locally without a server or remote assets. Output
paths must be new. Mailbox processing never fetches links/images, opens attachments,
or logs into an account. Inputs are limited to 25 MiB; MBOX to 1000 messages.
PDF, DOCX and text extraction is supported; scanned-image OCR is not.

`mailbox FILE --query TEXT --case ID` searches imported message fields/body.
Full message bodies are stored locally by mailbox imports. The original input
files are not copied to case storage: preserve them separately if needed.

## Explicit network operations

```bash
./run.sh scan domain example.com --case "$CASE_ID"
./run.sh auth example.com --case "$CASE_ID"
./run.sh dkim ./original-message.eml --case "$CASE_ID"
./run.sh lookup pgp 'your-address@example.com' --case "$CASE_ID"
./run.sh lookup rdap example.com --case "$CASE_ID"
./run.sh archive 'https://example.com/contact' --limit 3 --case "$CASE_ID"
./run.sh blocklist 192.0.2.1 --zone YOUR_AUTHORISED_DNSBL_ZONE --case "$CASE_ID"
```

Use your actual in-scope address/domain instead of the examples when appropriate.
DNS and selected HTTP providers receive the queried indicator. `auth` also requests
the domain's MTA-STS HTTPS policy; `dkim` queries signature key DNS. DKIM checks the
first signature with current keys; it does not reconstruct historical keys or prove
sender identity. DNSBL answers require zone-specific interpretation.

`archive` queries only the supplied page through the Wayback service and retrieves
up to three early index snapshots; it does not fetch the original website or follow
redirects. Changes in extracted addresses are observations, not proof of removal.

## Provider keys and upstream tools

```bash
read -rsp 'Hunter key: ' HUNTER_API_KEY; echo
export HUNTER_API_KEY
./run.sh lookup hunter-search example.com --case "$CASE_ID"
./run.sh lookup hunter-verify 'your-address@example.com' --case "$CASE_ID"
unset HUNTER_API_KEY
```

HIBP uses `HIBP_API_KEY` and `scan email ADDRESS --modules hibp --case ID`.
EmailRep uses `EMAILREP_API_KEY` and `--modules emailrep`. Keys are read from the
environment, not saved to cases. HIBP returns breach metadata, not passwords.
Provider quotas and charges apply. Lookup commands make bounded requests with no
automatic retries; `budget` can set rolling request caps and your own per-request cost estimate; provider quota synchronization is not implemented.
Hunter verifier may perform active mailbox probing at the provider.

```bash
./run.sh accounts ghunt 'your-address@example.com' --case "$CASE_ID"
./run.sh accounts holehe 'your-address@example.com' --case "$CASE_ID"
./run.sh harvest example.com --case "$CASE_ID" --sources crtsh,certspotter
./run.sh import-harvester ./result.jsonl --domain example.com --case "$CASE_ID"
./run.sh health
```

See INTEGRATIONS.md for separate installations, authentication and exact boundaries.

## Imported claims, review and redaction

```bash
./run.sh import-claims examples/claims.json --case "$CASE_ID"
./run.sh case show "$CASE_ID"
./run.sh compare --case "$CASE_ID" --before RUN_ID_1 --after RUN_ID_2
./run.sh review --case "$CASE_ID" --run RUN_ID --reviewer 'Anil' --decision needs-evidence --note 'Two providers share the same declared source.'
./run.sh removal --case "$CASE_ID" --email 'your-address@example.com' --source 'https://example.com/contact' --status requested --note 'Request submitted separately by analyst.'
./run.sh redact --case "$CASE_ID" --out ./redacted-1
```

Claims require email, provider, source, claim, value and observed_at (ISO timestamp
with timezone). Optional upstream_source records shared origin. See the example.
Analyst names are self-declared, not authenticated. Review/removal events do not
change original evidence, enforce approval, send messages or submit removal requests.

Redacted exports omit body/payment fields and stored hashes, and pseudonymise email
addresses. Use `--terms-file secrets.txt` (one exact term per line) to remove known
secrets. Names, domains and indirect identifiers need manual review before sharing.
The redaction mapping is not exported. Reports are private derivatives, not certified
anonymisation. Original case data remains unchanged.

## Scheduled local alerts

```bash
./run.sh watch 'student@example.com' --case "$CASE_ID" --profile offline --interval 86400
./run.sh watches
./run.sh run-due --limit 10
./run.sh disable-watch WATCH_ID
```

For recurring execution, add your chosen absolute launcher path to your own cron:
`0 * * * * /absolute/path/mailintel-v1.4/.venv/bin/mailintel run-due --limit 10`
No cron job is installed automatically. The output is a JSON list with change/error
flags. Watches support only offline or DNS scans; no paid API batches, push messages,
automatic retention or secret storage. Jobs reserve their next slot before running;
if interrupted, the next scheduled interval is used rather than an immediate retry.

## Storage, integrity and development

Default database: `~/.local/share/mailintel/cases.sqlite3`. Use global
`--data-dir PATH` before the subcommand, or MAILINTEL_DATA_DIR, to isolate a project.
The 0.1.0 case schema remains readable; watches and budget tracking add tables without rewriting existing runs.
Back up the database while no command is writing. Stored data is NOT encrypted.
Evidence hashes detect accidental payload edits, not a malicious database administrator.
A review event is an analyst claim, not a cryptographic signature.

```bash
./run.sh verify --case "$CASE_ID"
.venv/bin/python -m unittest discover -s tests -v
sha256sum -c SHA256SUMS
```

No automatic data deletion. Remove an unwanted case data directory only after
confirming it contains no needed evidence. To uninstall, remove the user launcher
only if it points here, then remove the extracted directory; case data is separate.
See VALIDATION.md for actual test results and untested boundaries.

## Local provider budgets

```bash
./run.sh budget hunter --max-requests 20 --cost-per-request 0.01
./run.sh usage
```

Costs are estimates in the units you choose, not provider invoices. Counts are
request reservations (failures count too) in the last 24 hours, and only cover
commands sharing this data directory. External GHunt/Holehe/theHarvester usage
is not counted. A provider's real limits may be lower than your local cap.

## Numbered feature and command reference

Run commands from the project directory after installation. First create or select
an investigation with `CASE_ID=$(./run.sh case new --name 'Email assessment')`.
When reopening your terminal, use `./run.sh case list` and then
`CASE_ID='the-existing-id'`. Replace example addresses with your intended in-scope
indicators. A run ID is printed after a saved analysis; it is different from a case ID.

| No. | Feature and benefit | Command / requirement |
|---|---|---|
| 1 | Terminal menu for common actions | `bash menu.sh` |
| 2 | Fictional offline training and example reports | `bash demo.sh`; see `examples/EXPECTED.md` |
| 3 | Create an investigation | `CASE_ID=$(./run.sh case new --name 'Email assessment')` |
| 4 | Resume a case and inspect saved run IDs | `./run.sh case list` and `./run.sh case show "$CASE_ID"` |
| 5 | Validate email syntax and disposable-domain membership | `./run.sh scan email 'person@example.com' --case "$CASE_ID" --profile offline` |
| 6 | Collect domain mail DNS records | `./run.sh scan domain example.com --case "$CASE_ID"`; internet |
| 7 | Look up a known DKIM selector | `./run.sh scan domain example.com --case "$CASE_ID" --modules dns --dkim-selector selector1`; internet |
| 8 | Follow SPF references, examine MX destinations, DMARC fallback and MTA-STS | `./run.sh auth example.com --case "$CASE_ID"`; internet; not full policy enforcement |
| 9 | Analyse a saved message, headers and reply destinations | `./run.sh mailbox ./message.eml --case "$CASE_ID"`; offline |
| 10 | Analyse exported mailbox threads and parent-message changes | `./run.sh mailbox ./messages.mbox --case "$CASE_ID"`; offline |
| 11 | Search message fields and bodies | `./run.sh mailbox ./messages.mbox --query 'invoice' --case "$CASE_ID"`; offline |
| 12 | Detect link-display mismatches, possible tracking images and attachment signatures | Included in `mailbox`; no remote content loaded; not malware classification |
| 13 | Verify the first DKIM signature with current DNS keys | `./run.sh dkim ./original-message.eml --case "$CASE_ID"`; internet |
| 14 | Extract document addresses with locations/context | `./run.sh extract ./contacts.pdf --case "$CASE_ID"`; PDF/DOCX/TXT/HTML/CSV; no OCR |
| 15 | Flag role addresses and possible Gmail aliases | Included in extraction/insights; heuristic labels, no automatic identity merging |
| 16 | Find name/address patterns from known contacts | `./run.sh patterns examples/names.csv --case "$CASE_ID"`; CSV columns `first,last,email` |
| 17 | Generate possible email addresses | `./run.sh candidates --first Alice --last Smith --domain example.com --case "$CASE_ID"`; all results unverified guesses |
| 18 | Generate local lookalike-domain candidates | `./run.sh lookalikes example.com --case "$CASE_ID"`; does not check registration or intent |
| 19 | Process an email list | `./run.sh batch examples/emails.txt --case "$CASE_ID"`; add `--profile passive --max-items 100` for DNS; no paid batches |
| 20 | Discover company emails with Hunter | `./run.sh lookup hunter-search example.com --case "$CASE_ID"`; HUNTER_API_KEY |
| 21 | Ask Hunter for deliverability results | `./run.sh lookup hunter-verify 'person@example.com' --case "$CASE_ID"`; HUNTER_API_KEY; may cause provider-side SMTP checks |
| 22 | Retrieve breach metadata from HIBP | `./run.sh scan email 'person@example.com' --case "$CASE_ID" --modules hibp`; HIBP_API_KEY |
| 23 | Retrieve EmailRep reputation observations | `./run.sh scan email 'person@example.com' --case "$CASE_ID" --modules emailrep`; provider access/key requirements apply |
| 24 | Run GHunt account research | `./run.sh accounts ghunt 'person@example.com' --case "$CASE_ID"`; separate installation and login |
| 25 | Run Holehe account checks | `./run.sh accounts holehe 'person@example.com' --case "$CASE_ID"`; separate installation; third-party interaction |
| 26 | Run theHarvester discovery | `./run.sh harvest example.com --case "$CASE_ID" --sources crtsh,certspotter`; separate installation |
| 27 | Import existing theHarvester results | `./run.sh import-harvester ./result.jsonl --domain example.com --case "$CASE_ID"`; offline; domain filtering |
| 28 | Look up published PGP key material | `./run.sh lookup pgp 'person@example.com' --case "$CASE_ID"`; internet; not ownership verification |
| 29 | Find the domain's registry lookup destination | `./run.sh lookup rdap example.com --case "$CASE_ID"`; usually returns a redirect for manual follow-up |
| 30 | Collect archived occurrences and appearance changes | `./run.sh archive 'https://example.com/contact' --limit 3 --case "$CASE_ID"`; exact page, up to three early snapshots |
| 31 | Query a chosen IPv4 email blocklist | `./run.sh blocklist 192.0.2.1 --zone YOUR_AUTHORISED_DNSBL_ZONE --case "$CASE_ID"`; interpret zone codes manually |
| 32 | Read DMARC aggregate XML reports | `./run.sh dmarc examples/dmarc.xml --case "$CASE_ID"`; offline, plain XML |
| 33 | Import source-labelled external claims | `./run.sh import-claims examples/claims.json --case "$CASE_ID"`; MailIntel exchange format |
| 34 | Combine findings, timelines and conflicts | `./run.sh insights --case "$CASE_ID"`; includes declared source grouping and coverage gaps |
| 35 | Draw evidence relationships | `./run.sh graph --case "$CASE_ID" --out ./graph-1`; open `graph-1/graph.html` |
| 36 | Compare two runs for the same indicator and kind | `./run.sh compare --case "$CASE_ID" --before RUN_ID_1 --after RUN_ID_2` |
| 37 | Record an analyst review without overwriting evidence | `./run.sh review --case "$CASE_ID" --run RUN_ID --reviewer 'Anil' --decision needs-evidence --note 'Check original source.'` |
| 38 | Track exposure-removal work | `./run.sh removal --case "$CASE_ID" --email 'person@example.com' --source 'https://example.com/contact' --status requested --note 'Submitted separately.'`; sends nothing |
| 39 | Export HTML and JSON | `./run.sh report --case "$CASE_ID" --out ./report-1` |
| 40 | Create a redacted derivative | `./run.sh redact --case "$CASE_ID" --out ./redacted-1`; optional `--terms-file secrets.txt` |
| 41 | Export evidence ZIP with checksums | `./run.sh bundle --case "$CASE_ID" --out ./evidence-1.zip`; source input files remain separate |
| 42 | Verify stored payload hashes | `./run.sh verify --case "$CASE_ID"`; not digital signatures |
| 43 | Add and execute periodic checks | `./run.sh watch 'person@example.com' --case "$CASE_ID" --profile passive --interval 86400`; invoke `./run.sh run-due --limit 10` periodically |
| 44 | List or disable watches | `./run.sh watches` and `./run.sh disable-watch WATCH_ID` |
| 45 | Set local request and estimated-cost limits | `./run.sh budget hunter --max-requests 20 --cost-per-request 0.01`; see `./run.sh usage` |
| 46 | Inspect installation, keys and previous statuses | `./run.sh doctor`, `./run.sh health`, `./run.sh modules`, `./run.sh --version` |
| 47 | Get command-specific help | `./run.sh --help` or `./run.sh mailbox --help` |
| 48 | Isolate project data | `export MAILINTEL_DATA_DIR="$PWD/project-data"`; set this again when resuming that project |

### Input formats and result meanings

`names.csv`:

```csv
first,last,email
Alice,Smith,alice.smith@example.com
Bob,Jones,bob.jones@example.com
```

`emails.txt`: one email per line; duplicate exact lines are removed. All addresses
are validated before a batch begins. Case IDs must exist before queries run.

`claims.json`:

```json
[
  {
    "email": "person@example.com",
    "provider": "Analyst-supplied source",
    "source": "https://example.com/contact",
    "claim": "publicly_listed",
    "value": "present",
    "observed_at": "2026-09-09T10:00:00Z",
    "upstream_source": "Original contact page"
  }
]
```

Timestamps require a timezone. `upstream_source` is optional and identifies a
shared origin; importing a provider's name does not mean MailIntel queried it.

| Result | Interpretation |
|---|---|
| `valid_syntax` | Address format accepted; no deliverability or ownership proof |
| `listed` / `not_listed` | Membership in the bundled disposable list |
| `observed` | Evidence or a provider response was collected; inspect its detail |
| `not_found` | That source returned no matching result; not universal absence |
| `unverified_guess` | Generated candidate, not a discovered mailbox |
| `not_configured` | Required key or separate executable missing |
| `rate_limited` | Provider cooldown or local cap prevents the request |
| `partial` / `error` | Missing/failed evidence; never treat it as a clean result |

Typical command exit codes: 0 completed, 2 invalid input or an indicated
failed/partial result, 130 user interruption. Some orchestration commands, such as
`run-due`, return a JSON list whose error fields also need inspection.

## Troubleshooting

| Symptom | What to do |
|---|---|
| `python3: command not found` / venv unavailable | Install Python and python3-venv, then rerun `bash install.sh` |
| `Permission denied` when running a script | Use `bash run.sh ...`, or restore execute permission with `chmod +x *.sh` |
| `Unknown case ID` | Run `./run.sh case list`; check MAILINTEL_DATA_DIR points at the correct project |
| `$CASE_ID` is empty after opening a new terminal | Set `CASE_ID='existing-case-id'` again |
| Report output already exists | Pick a new output directory, such as `report-2` |
| Provider says `not_configured` | Set the corresponding key or install the upstream executable |
| DNS timeout / provider error | Check connectivity; preserve it as missing evidence, not a negative result |
| Rate-limited result | Inspect provider limits and local budgets; wait rather than evade the limit |
| `.mbox` is too large | Split/export smaller portions; 25 MiB and 1000-message limits apply |
| No text from a scanned PDF | OCR is not provided; supply a searchable PDF or extracted text |
| MailIntel command points to an older installation | Use `bash run.sh` inside this project's directory |

## Licence and intended use

Original MailIntel code is MIT licensed. Bundled third-party code and datasets have
separate notices: see LICENSE, THIRD_PARTY.md, PSL_LICENSE.txt and the licences
inside the dependency wheels. Keep those notices when redistributing this package.
Use the toolkit for evidence you are authorised to analyse and respect provider
access conditions. No OSCP exam approval is claimed. Commercial integrations remain
account-dependent and live end-to-end validation is outstanding as documented.
