"""Turns results into something a person can read and an auditor can file."""
import json
from dataclasses import asdict
from datetime import datetime, timezone

from .checks import FAIL, PASS, UNKNOWN

MARK = {PASS: 'PASS', FAIL: 'FAIL', UNKNOWN: ' ?? '}
NOTE = ('This is a readiness check of common AWS settings. It is not an audit, and passing it does not make '
        'an account SOC 2 compliant: an independent CPA firm decides that.')


def counts(results):
    return {status: sum(1 for r in results if r.status == status) for status in (PASS, FAIL, UNKNOWN)}


def as_text(results, account_id=None):
    c = counts(results)
    lines = [f"SOC 2 readiness check for AWS{f' — account {account_id}' if account_id else ''}", '']
    for r in results:
        lines.append(f'[{MARK[r.status]}] {r.id:6} {r.title}')
        if r.status != PASS:
            lines.append(f'         {r.detail}')
            for resource in r.resources[:10]:
                lines.append(f'           - {resource}')
            if len(r.resources) > 10:
                lines.append(f'           … and {len(r.resources) - 10} more')
            if r.fix:
                lines.append(f'         Fix: {r.fix}')
    lines += ['', f"{c[PASS]} passed · {c[FAIL]} failed · {c[UNKNOWN]} could not be checked", '', NOTE]
    return '\n'.join(lines)


def as_markdown(results, account_id=None, when=None):
    c = counts(results)
    when = when or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    out = ['# SOC 2 readiness check — AWS', '', f'- **Account:** {account_id or "unknown"}', f'- **Run:** {when}',
           f'- **Result:** {c[PASS]} passed · {c[FAIL]} failed · {c[UNKNOWN]} could not be checked', '', f'> {NOTE}', '',
           '| Check | What | Usually mapped to | Result |', '|---|---|---|---|']
    out += [f'| {r.id} | {r.title} | {r.criteria} | {r.status} |' for r in results]
    todo = [r for r in results if r.status != PASS]
    if todo:
        out += ['', '## To fix or review', '']
        for r in todo:
            out += [f'### {r.id} · {r.title}', '', f'**{r.status}** — {r.detail}', '']
            out += [f'- `{resource}`' for resource in r.resources]
            if r.fix:
                out += ['', f'**Fix:** {r.fix}']
            out.append('')
    return '\n'.join(out)


def as_json(results, account_id=None):
    return json.dumps({'account': account_id, 'summary': counts(results), 'results': [asdict(r) for r in results]}, indent=2)
