# Third party components

The wheelhouse contains unmodified wheels for the dependencies in requirements.lock.
Their licence and copyright notices are retained inside each wheel's .dist-info
metadata and are installed with the packages. They are not relicensed as MailIntel.

The disposable-domain dataset is redistributed with its CC0 licence, source URL,
commit, entry count and SHA256 in mailintel/data.

theHarvester is optional and not redistributed. setup-harvester.sh installs the
upstream source revision in a separate tool environment. The operator remains
responsible for its licence obligations and any configured provider accounts.

API provider terms apply separately from software licences:
- https://haveibeenpwned.com/API/v3
- https://haveibeenpwned.com/TermsOfUse
- https://docs.sublime.security/reference/emailrep-introduction

Full library versions and distribution hashes are in requirements.lock and uv.lock.

## Additional v1.4 components

pypdf 6.18.0 (BSD-3-Clause), dkimpy 1.1.8 (BSD), publicsuffix2 2.20191221
(MPL-2.0) are bundled as wheels with their upstream licence notices. The public
suffix dataset is a separate snapshot from publicsuffix.org, with metadata and
SHA256 in mailintel/data/psl_metadata.json, under MPL-2.0. dkimpy was built into
a pure-Python wheel from its PyPI source archive in this build environment.
The locally built wheel hash is pinned in requirements.lock.
