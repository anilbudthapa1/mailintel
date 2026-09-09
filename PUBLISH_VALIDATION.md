# Publishing script validation

The script is designed for first publication into a NEW github.com repository.
It was validated locally; no real GitHub account or remote repository was used.

Checks: bash syntax/help, default no-network preparation, exact staged-file list,
exclusion of unlisted database/credential/report files, modified-file refusal,
symlink refusal, existing-output refusal, and publish/release execution using a
stub GitHub CLI plus a real local bare Git repository. The local transport test
checks that main and tag v1.4.0 arrive and that release asset arguments reference
valid files. GitHub authentication, API access, permissions and live upload remain
untested. This is not a guarantee that all provider-side failures are handled.

Application validation remains documented separately in VALIDATION.md. The
application source and wheel are unchanged by this documentation/publishing update.
