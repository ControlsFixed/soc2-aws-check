"""python -m soc2_check [--profile NAME] [--regions eu-west-1,us-east-1] [--markdown report.md] [--json report.json]"""
import argparse
import sys

from .checks import FAIL, run_all
from .report import as_json, as_markdown, as_text


def main(argv=None):
    parser = argparse.ArgumentParser(prog='soc2_check', description='Read-only SOC 2 readiness check for an AWS account.')
    parser.add_argument('--profile', help='AWS profile to use (default: your default credentials)')
    parser.add_argument('--regions', help='Comma-separated regions to check (default: every enabled region)')
    parser.add_argument('--markdown', metavar='FILE', help='Also write a Markdown report')
    parser.add_argument('--json', metavar='FILE', help='Also write a JSON report')
    args = parser.parse_args(argv)

    try:
        import boto3
    except ImportError:
        print('This tool needs boto3. Install it with: pip install boto3', file=sys.stderr)
        return 2
    from .collect import collect

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    if session.get_credentials() is None:
        print('No AWS credentials found. Configure a read-only profile first (see README), then run again.', file=sys.stderr)
        return 2

    regions = [r.strip() for r in args.regions.split(',') if r.strip()] if args.regions else None
    data = collect(session, regions, progress=lambda text: print(f'  reading {text}…', file=sys.stderr))
    results = run_all(data)
    account = data.get('account_id')
    print(as_text(results, account))
    if args.markdown:
        with open(args.markdown, 'w', encoding='utf-8') as handle:
            handle.write(as_markdown(results, account))
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as handle:
            handle.write(as_json(results, account))
    return 1 if any(r.status == FAIL for r in results) else 0


if __name__ == '__main__':
    sys.exit(main())
