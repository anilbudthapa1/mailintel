# MailIntel v1.4.0

Email-only Linux CLI and terminal menu, with offline dependencies and fictional
training examples. This release consolidates email/message analysis and case
workflows; it does not claim full completion of every proposed roadmap feature.

Features include email syntax/disposable checks, document and mailbox analysis,
DKIM verification, DMARC XML import, bounded DNS/authentication analysis, explicit
provider adapters and upstream runners, archive collection, graphs, analyst reviews,
redacted exports, evidence bundles, local watches and provider request budgets.

Validation: 41 application tests passed on Linux/Python 3.12.14 in the build
workspace, plus clean installation and offline training demo. Live commercial
accounts and real external tool integrations remain unverified. See VALIDATION.md,
FEATURE_STATUS.md and INTEGRATIONS.md before relying on a particular result.

GitHub packaging revision: expanded README, an allowlisted upload script and
manifest, .gitignore and these release notes. Application source is unchanged from
the delivered 1.4.0 build. Do not overwrite an existing v1.4.0 tag in another repo.
