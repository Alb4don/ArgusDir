#!/usr/bin/env python3

import argparse
import json
import os
import random
import re
import sys
from collections import Counter
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class _NoColor:
    def __getattr__(self, _name):
        return ''


def _init_color():
    try:
        from colorama import init as colorama_init, Fore, Style
    except ImportError:
        return False, _NoColor(), _NoColor()
    try:
        stream = sys.stdout
        if stream is not None and hasattr(stream, 'isatty') and stream.isatty():
            colorama_init(autoreset=True)
            return True, Fore, Style
    except Exception:
        pass
    return False, _NoColor(), _NoColor()


COLOR_AVAILABLE, Fore, Style = _init_color()

TOOL_NAME = "ArgusTriage"
TOOL_TITLE = "ArgusTriage - Conversational Findings Triage"
TOOL_VERSION = "1.0.0"

SEVERITY_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
SEVERITY_COLORS = {
    'critical': Fore.RED + Style.BRIGHT,
    'high': Fore.RED,
    'medium': Fore.YELLOW,
    'low': Fore.CYAN,
    'info': Fore.WHITE,
}

RULES = [
    (re.compile(r'(^|/)\.git(/|$)', re.I), 'critical',
     'Exposed Git metadata can leak full source history and credentials.',
     'Block access to .git, purge the directory from the web root, rotate any committed secrets.'),
    (re.compile(r'(^|/)\.svn(/|$)', re.I), 'critical',
     'Exposed SVN metadata can leak source code and repository structure.',
     'Remove .svn from the web root and restrict access at the server level.'),
    (re.compile(r'(^|/)\.(env|htpasswd)(/|$|\.)', re.I), 'critical',
     'Environment or credential files commonly contain secrets, keys, and DB passwords.',
     'Deny access to dotfiles, move secrets out of the web root, rotate exposed credentials.'),
    (re.compile(r'(wp-config|config\.(php|inc|ya?ml|json)|settings\.py)(\.|$)', re.I), 'critical',
     'Application config files often hold database and API credentials.',
     'Restrict access, confirm the file is not served as plaintext, rotate any exposed secrets.'),
    (re.compile(r'\.(sql|dump|db|sqlite3?)(\.|$)', re.I), 'critical',
     'Database exports can expose entire datasets including user records.',
     'Remove the dump from the web root immediately and review access logs for prior downloads.'),
    (re.compile(r'(id_rsa|\.pem|\.ppk|\.key)(\.|$)', re.I), 'critical',
     'Private key material enables impersonation or lateral movement.',
     'Revoke and rotate the key, remove it from the web root, audit usage.'),
    (re.compile(r'\.(bak|old|orig|save|swp|swo|tmp|copy)(\.|$)', re.I), 'high',
     'Backup or editor temp files frequently expose source or prior configs.',
     'Delete stray backups from the web root and add server rules to block these extensions.'),
    (re.compile(r'\.(zip|tar|gz|tgz|rar|7z)(\.|$)', re.I), 'high',
     'Archives in the web root may contain source, backups, or sensitive data.',
     'Remove the archive and confirm it was not indexed or downloaded.'),
    (re.compile(r'(phpinfo|info\.php)(\.|$)', re.I), 'high',
     'phpinfo discloses environment, paths, and loaded modules useful to an attacker.',
     'Delete the file; it should never be reachable in production.'),
    (re.compile(r'(server-status|server-info)(/|$)', re.I), 'high',
     'Server status pages disclose live requests, client IPs, and internal paths.',
     'Restrict mod_status to localhost or disable it in production.'),
    (re.compile(r'(^|/)(phpmyadmin|adminer|pma)(/|$)', re.I), 'high',
     'Exposed DB admin panels are a direct path to data if credentials are weak.',
     'Restrict by IP allowlist or VPN, enforce strong auth, keep the panel patched.'),
    (re.compile(r'(^|/)actuator(/|$)', re.I), 'high',
     'Spring Boot actuator endpoints can leak config, env, and heap data.',
     'Disable sensitive actuator endpoints or secure them behind authentication.'),
    (re.compile(r'(^|/)(admin|administrator|manage|console|dashboard)(/|$)', re.I), 'medium',
     'Administrative surface; its exposure defines part of the attack surface.',
     'Confirm strong authentication, rate limiting, and that it is not reachable unauthenticated.'),
    (re.compile(r'(^|/)(login|signin|auth|portal)(/|$)', re.I), 'medium',
     'Authentication entry point worth reviewing for weak controls.',
     'Check for lockout, MFA, and credential-stuffing protection.'),
    (re.compile(r'(^|/)api(/|$|\.)', re.I), 'medium',
     'API surface may expose undocumented or unauthenticated endpoints.',
     'Enumerate methods and auth requirements; review for broken access control.'),
    (re.compile(r'(^|/)(backup|backups|bak)(/|$)', re.I), 'high',
     'Backup directories routinely contain sensitive archives.',
     'Restrict access and relocate backups outside the web root.'),
]


def color(text, col, use_color):
    if not use_color or not COLOR_AVAILABLE:
        return text
    return f"{col}{text}{Style.RESET_ALL}"


def clamp_down(severity, floor='medium'):
    rank = max(SEVERITY_RANK[floor], SEVERITY_RANK[severity] - 1)
    for label, value in SEVERITY_RANK.items():
        if value == rank:
            return label
    return floor


def path_of(url):
    try:
        parsed = urlparse(url)
        return (parsed.path or '/')
    except ValueError:
        return url


def triage_finding(finding):
    url = finding.get('url', '')
    status = int(finding.get('status', 0) or 0)
    dir_listing = bool(finding.get('directory_listing'))
    target = path_of(url)

    severity, reason, recommendation = 'info', 'Reachable resource.', 'Review whether this should be publicly accessible.'
    for pattern, sev, why, fix in RULES:
        if pattern.search(target):
            severity, reason, recommendation = sev, why, fix
            break

    if dir_listing and SEVERITY_RANK[severity] < SEVERITY_RANK['high']:
        severity = 'high'
        reason = 'Directory listing is enabled, exposing file names and structure.'
        recommendation = 'Disable autoindex/directory browsing on the server.'

    accessible = status in (200, 206) or dir_listing
    note = ''
    if status in (401, 403):
        accessible = False
        note = 'present but access-controlled; verify the control cannot be bypassed'
        if severity == 'critical':
            severity = clamp_down('critical', 'high')
    elif status in (301, 302, 303, 307, 308):
        note = 'redirects; follow the target to confirm what is exposed'
    elif status == 500:
        note = 'server error; may indicate an injection or misconfiguration surface'
        if SEVERITY_RANK[severity] < SEVERITY_RANK['medium']:
            severity = 'medium'
            reason = 'Server error on this path can leak stack traces or indicate an unstable endpoint.'
            recommendation = 'Suppress detailed errors in production and investigate the cause.'

    score = SEVERITY_RANK[severity] * 100 + (10 if accessible else 0) + max(0, 5 - abs(status - 200) // 100)
    return {
        'url': url, 'status': status, 'severity': severity, 'score': score,
        'accessible': accessible, 'reason': reason, 'recommendation': recommendation,
        'note': note, 'cms': finding.get('cms'), 'directory_listing': dir_listing,
    }


def load_findings(source):
    if source == '-':
        raw = sys.stdin.read()
    else:
        if not os.path.isfile(source):
            raise ValueError(f"findings file not found: {source}")
        with open(source, 'r', encoding='utf-8') as fh:
            raw = fh.read()
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("input is not valid JSON")
    if isinstance(data, dict):
        for key in ('results', 'findings', 'paths'):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of findings")
    cleaned = [f for f in data if isinstance(f, dict) and f.get('url')]
    return cleaned


class LLMBridge:
    def __init__(self, use_color):
        self.use_color = use_color
        self.endpoint = os.environ.get('ARGUS_LLM_ENDPOINT', '').strip()
        self.key = os.environ.get('ARGUS_LLM_KEY', '').strip()
        self.model = os.environ.get('ARGUS_LLM_MODEL', 'gpt-4o-mini').strip()
        self.ready = bool(self.endpoint and self.key and REQUESTS_AVAILABLE)

    def warning(self):
        host = urlparse(self.endpoint).netloc or self.endpoint
        return (f"LLM mode on: triage facts will be sent to {host}. "
                "Do not enable this on engagements whose scope or NDA forbids third-party processing.")

    def rephrase(self, question, grounded_facts):
        if not self.ready:
            return None
        system = (
            "You are a security findings triage assistant speaking with a penetration tester. "
            "Use ONLY the JSON facts provided. Never invent paths, CVEs, severities, or results not present. "
            "Severities are already assigned by a deterministic engine; do not change them. "
            "Answer conversationally and concisely, like a colleague."
        )
        payload = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': system},
                {'role': 'user', 'content': f"FACTS:\n{json.dumps(grounded_facts)[:6000]}\n\nQUESTION: {question}"},
            ],
            'temperature': 0.4,
            'max_tokens': 400,
        }
        headers = {'Authorization': f"Bearer {self.key}", 'Content-Type': 'application/json'}
        try:
            resp = requests.post(self.endpoint, json=payload, headers=headers, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            return data['choices'][0]['message']['content'].strip()
        except Exception:
            return None


class TriageSession:
    OPENERS = ("Here's what I'm seeing.", "Alright.", "Looking at it now.", "Got it.", "Sure.")

    def __init__(self, findings, use_color, llm=None):
        self.use_color = use_color
        self.llm = llm
        self.items = sorted((triage_finding(f) for f in findings), key=lambda x: x['score'], reverse=True)

    def _sev(self, label):
        return color(label.upper(), SEVERITY_COLORS.get(label, ''), self.use_color)

    def _line(self, item):
        acc = 'accessible' if item['accessible'] else 'protected/other'
        tail = f" - {item['note']}" if item['note'] else ''
        return f"  [{item['status']}] {self._sev(item['severity'])}  {item['url']}  ({acc}){tail}"

    def counts(self):
        return Counter(i['severity'] for i in self.items)

    def summary_text(self):
        if not self.items:
            return "There are no findings to look at — the scan came back empty."
        c = self.counts()
        parts = [f"{c[s]} {s}" for s in ('critical', 'high', 'medium', 'low', 'info') if c.get(s)]
        headline = f"{random.choice(self.OPENERS)} {len(self.items)} findings total — " + ', '.join(parts) + "."
        top = [i for i in self.items if i['severity'] in ('critical', 'high')][:5]
        if not top:
            return headline + " Nothing jumps out as critical; it's mostly low-signal stuff."
        lines = '\n'.join(self._line(i) for i in top)
        lead = "The ones I'd look at first:" if len(top) > 1 else "The one I'd look at first:"
        return f"{headline}\n\n{lead}\n{lines}"

    def by_severity(self, wanted):
        picked = [i for i in self.items if i['severity'] in wanted]
        if not picked:
            names = ' or '.join(wanted)
            return f"Nothing at {names} level, which is good news. Want the full list instead?"
        lines = '\n'.join(self._line(i) for i in picked)
        return f"{random.choice(self.OPENERS)} {len(picked)} at that level:\n{lines}"

    def by_status(self, status):
        picked = [i for i in self.items if i['status'] == status]
        if not picked:
            return f"No {status}s in here. Try 'summary' to see what did come back."
        lines = '\n'.join(self._line(i) for i in picked)
        verb = {401: "behind auth", 403: "forbidden", 500: "erroring", 200: "serving content"}.get(status, "")
        tag = f" ({verb})" if verb else ""
        return f"{len(picked)} path(s) returning {status}{tag}:\n{lines}"

    def explain(self, needle):
        needle = needle.strip().strip('"\'')
        if not needle:
            return "Which path do you want me to dig into? Give me a name or part of the URL."
        matches = [i for i in self.items if needle.lower() in i['url'].lower()]
        if not matches:
            return f"I don't have anything matching '{needle}'. Type 'list' and I'll show you everything I've got."
        item = matches[0]
        extra = f"\n  Note: {item['note']}" if item['note'] else ''
        more = f"\n  (+{len(matches) - 1} other matching paths)" if len(matches) > 1 else ''
        return (f"{item['url']} — {self._sev(item['severity'])}, returned {item['status']}.\n"
                f"  Why it matters: {item['reason']}\n"
                f"  What I'd do: {item['recommendation']}{extra}{more}")

    def recommend(self):
        if not self.items:
            return "Nothing to act on — the findings list is empty."
        top = [i for i in self.items if i['severity'] in ('critical', 'high')]
        if not top:
            return ("Nothing urgent. I'd still manually confirm the admin/login surfaces enforce real auth, "
                    "then move on — this target isn't leaking much.")
        steps = []
        for i in top[:4]:
            steps.append(f"  - {i['url']}: {i['recommendation']}")
        head = "If I were you, I'd work top-down:" if len(steps) > 1 else "Here's where I'd start:"
        return head + "\n" + '\n'.join(steps)

    def list_all(self):
        if not self.items:
            return "Empty — nothing was discovered."
        return '\n'.join(self._line(i) for i in self.items)

    def report(self):
        lines = [f"{TOOL_TITLE} v{TOOL_VERSION}", ""]
        c = self.counts()
        lines.append("severity breakdown: " + ', '.join(f"{c[s]} {s}" for s in ('critical', 'high', 'medium', 'low', 'info') if c.get(s)))
        lines.append("")
        for item in self.items:
            lines.append(f"[{item['severity'].upper()}] {item['url']} ({item['status']})")
            lines.append(f"    {item['reason']}")
            lines.append(f"    fix: {item['recommendation']}")
            if item['note']:
                lines.append(f"    note: {item['note']}")
        return '\n'.join(lines)

    def grounded_facts(self):
        return [
            {'url': i['url'], 'status': i['status'], 'severity': i['severity'],
             'accessible': i['accessible'], 'reason': i['reason'], 'recommendation': i['recommendation']}
            for i in self.items
        ]

    def answer(self, text):
        q = text.strip()
        low = q.lower()
        if not q:
            return ""
        if low in ('quit', 'exit', 'bye', 'q', ':q'):
            return None
        if low in ('help', '?', 'what can you do', 'commands'):
            return ("Ask me things like: 'summary', 'what's critical', 'show the 403s', "
                    "'explain /admin', 'what should I do next', 'list everything', or 'quit'.")

        deterministic = self._route(low, q)

        if self.llm and self.llm.ready:
            phrased = self.llm.rephrase(q, self.grounded_facts())
            if phrased:
                return phrased
        return deterministic

    def _route(self, low, original):
        if any(w in low for w in ('summary', 'overview', 'recap', 'how did it go', 'what did you find', "what's there")):
            return self.summary_text()
        if any(w in low for w in ('next', 'should i do', 'recommend', 'advice', 'where do i start', 'prioriti')):
            return self.recommend()
        if 'critical' in low and 'high' in low:
            return self.by_severity({'critical', 'high'})
        if 'critical' in low or 'worst' in low or 'most serious' in low:
            return self.by_severity({'critical'})
        if 'high' in low or 'important' in low or 'serious' in low or 'matter' in low:
            return self.by_severity({'critical', 'high'})
        if 'medium' in low:
            return self.by_severity({'medium'})
        if any(w in low for w in ('list', 'everything', 'show all', 'all findings', 'dump')):
            return self.list_all()
        if any(w in low for w in ('how many', 'count', 'total', 'number of')):
            c = self.counts()
            return (f"{len(self.items)} findings in total — "
                    + ', '.join(f"{c[s]} {s}" for s in ('critical', 'high', 'medium', 'low', 'info') if c.get(s)) + ".")
        status_match = re.search(r'(?<!\d)(200|201|204|301|302|401|403|405|500|503)(?!\d)', low)
        if status_match and any(w in low for w in ('show', 'which', 'list', 'the', 'any', 'got', 'return')):
            return self.by_status(int(status_match.group(1)))
        m = re.search(r'(?:explain|why|about|tell me about|what about|detail on|dig into|look at)\s+(.+)', low)
        if m:
            token = re.sub(r'\b(is|are|the|that|this|dangerous|matter|means?)\b', '', m.group(1)).strip()
            return self.explain(token or m.group(1))
        for item in self.items:
            tail = path_of(item['url']).rstrip('/').split('/')[-1]
            if tail and tail.lower() in low:
                return self.explain(tail)
        if status_match:
            return self.by_status(int(status_match.group(1)))
        return ("I didn't quite follow. I can give you a 'summary', filter by severity or status, "
                "'explain' a specific path, or suggest 'next' steps. What do you need?")


def repl(session, use_color):
    print(color(f"{TOOL_TITLE} v{TOOL_VERSION}", Fore.CYAN + Style.BRIGHT, use_color))
    if session.llm and session.llm.ready:
        print(color("[!] " + session.llm.warning(), Fore.YELLOW, use_color))
    print(session.summary_text())
    print(color("\nAsk me anything about these findings. Type 'help' or 'quit'.\n", Fore.CYAN, use_color))
    while True:
        try:
            text = input(color("you > ", Fore.GREEN, use_color))
        except (EOFError, KeyboardInterrupt):
            print("\nClosing out. Stay safe out there.")
            return
        reply = session.answer(text)
        if reply is None:
            print("Later. Good hunting.")
            return
        if reply:
            print(color("argus > ", Fore.MAGENTA, use_color) + reply + "\n")


def build_parser():
    p = argparse.ArgumentParser(
        prog='argus_triage.py',
        description=f"{TOOL_TITLE} v{TOOL_VERSION} - triage ArgusDir results conversationally",
        epilog="Deterministic by default. --llm sends data to a third party you configure; use only in-scope.",
    )
    p.add_argument('-f', '--findings', required=True, help="scanner JSON output, or '-' for stdin")
    p.add_argument('--once', dest='once', help="answer a single question and exit")
    p.add_argument('--report', action='store_true', help="print a full triage report and exit")
    p.add_argument('--llm', action='store_true', help="enable grounded LLM phrasing (requires ARGUS_LLM_* env vars)")
    p.add_argument('--no-color', action='store_true', help="disable colored output")
    return p


def main():
    args = build_parser().parse_args()
    use_color = (not args.no_color) and COLOR_AVAILABLE

    try:
        findings = load_findings(args.findings)
    except ValueError as exc:
        print(color(f"[x] {exc}", Fore.RED, use_color))
        return 2

    llm = None
    if args.llm:
        llm = LLMBridge(use_color)
        if not llm.ready:
            missing = "requests library" if not REQUESTS_AVAILABLE else "ARGUS_LLM_ENDPOINT/ARGUS_LLM_KEY"
            print(color(f"[!] LLM requested but unavailable ({missing}); using the offline engine.", Fore.YELLOW, use_color))

    session = TriageSession(findings, use_color, llm)

    if args.report:
        print(session.report())
        return 0
    if args.once:
        reply = session.answer(args.once)
        print(reply if reply else "")
        return 0

    repl(session, use_color)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
