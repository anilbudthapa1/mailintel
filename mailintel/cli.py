import argparse
import json
import os
import sys
from pathlib import Path
from .core import Store


def parser():
    p = argparse.ArgumentParser(description='MailIntel: email OSINT case manager. APIs are explicitly selected.')
    p.add_argument('--version', action='version', version='MailIntel 1.4.0')
    p.add_argument('--data-dir', default=os.environ.get('MAILINTEL_DATA_DIR', str(Path.home() / '.local/share/mailintel')))
    sub = p.add_subparsers(dest='command', required=True)
    case = sub.add_parser('case').add_subparsers(dest='action', required=True)
    case.add_parser('new').add_argument('--name', required=True)
    case.add_parser('list')
    case.add_parser('show').add_argument('id')
    sub.add_parser('modules')
    sub.add_parser('doctor')
    scan = sub.add_parser('scan')
    scan.add_argument('kind', choices=['email', 'domain'])
    scan.add_argument('value')
    scan.add_argument('--case', required=True)
    scan.add_argument('--profile', choices=['offline', 'passive'], default='passive')
    scan.add_argument('--modules', help='Comma separated names. Default: syntax,disposable,dns; offline excludes DNS.')
    scan.add_argument('--dkim-selector')
    export = sub.add_parser('report')
    export.add_argument('--case', required=True)
    export.add_argument('--out', required=True, help='New output directory; will not overwrite existing reports')
    verify = sub.add_parser('verify')
    verify.add_argument('--case', required=True)
    imp = sub.add_parser('import-harvester')
    imp.add_argument('file')
    imp.add_argument('--domain', required=True)
    imp.add_argument('--case', required=True)
    harvest = sub.add_parser('harvest')
    harvest.add_argument('domain')
    harvest.add_argument('--case', required=True)
    harvest.add_argument('--sources', default='crtsh,certspotter')
    from .advanced_cli import add
    add(sub)
    return p


def main(argv=None):
    os.umask(0o077)
    p = parser()
    args = p.parse_args(argv)
    try:
        from .modules import REGISTRY, run_modules, domain_name
        if args.command == 'modules':
            for name, (kind, detail) in REGISTRY.items():
                print(f'{name:14} {kind:8} {detail}')
            print('theharvester   external Use harvest or import-harvester commands')
            return 0
        if args.command == 'doctor':
            import importlib.metadata
            import shutil
            from .harvester import PIN
            for dep in ['dnspython', 'email-validator', 'httpx']:
                print(f'{dep}: {importlib.metadata.version(dep)}')
            for var in ['HIBP_API_KEY', 'EMAILREP_API_KEY']:
                print(f'{var}: {"configured" if os.environ.get(var) else "not configured"}')
            print('theHarvester:', shutil.which('theHarvester') or 'not installed (optional)')
            print('Recommended theHarvester commit:', PIN)
            print('Default data directory:', args.data_dir)
            return 0
        store = Store(args.data_dir)
        try:
            from .advanced_cli import COMMANDS, run
            if args.command in COMMANDS:
                return run(args,store)
            if args.command == 'case':
                if args.action == 'new':
                    print(store.create(args.name))
                elif args.action == 'list':
                    print(json.dumps(store.cases(), indent=2))
                else:
                    print(json.dumps({'case': store.case(args.id), 'runs': store.runs(args.id)}, indent=2))
            elif args.command == 'scan':
                store.case(args.case)  # Validate before any network request.
                selected = args.modules.split(',') if args.modules else ['syntax', 'disposable'] + ([] if args.profile == 'offline' else ['dns'])
                findings = run_modules(args.kind, args.value, selected, args.profile, store, args.dkim_selector)
                rid = store.save(args.case, args.value, args.kind, args.profile, findings)
                print('Saved run:', rid)
                for item in findings:
                    print(f"{item['module']:14} {item['status']:18} {item['detail']}")
                return 2 if any(f['status'] in ('error', 'partial', 'not_configured', 'rate_limited') for f in findings) else 0
            elif args.command == 'report':
                from .reports import report
                print(report(store, args.case, args.out))
            elif args.command == 'verify':
                runs = store.runs(args.case)
                print(f'Integrity OK: {len(runs)} stored run(s). Hashes are not digital signatures.')
            elif args.command in ('import-harvester', 'harvest'):
                from .harvester import load_result, execute
                store.case(args.case)
                domain = domain_name(args.domain)
                if args.command == 'harvest':
                    finding = execute(domain, args.sources.split(','))
                    profile = 'passive'
                else:
                    finding = load_result(args.file, domain)
                    profile = 'import'
                rid = store.save(args.case, domain, 'domain', profile, [finding])
                print('Saved run:', rid)
                print(finding['status'] + ': ' + finding['detail'])
                return 0 if finding['status'] == 'observed' else 2
        finally:
            store.db.close()
        return 0
    except (ValueError, OSError) as e:
        print('Error:', str(e), file=sys.stderr)
        return 2
    except ImportError:
        print('Missing dependency. Run bash install.sh from the extracted project.', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('Cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
