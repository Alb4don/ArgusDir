#!/usr/bin/env python3

import argparse
import random
import re
import sys
import types
from os import path

sys.path.insert(0, path.dirname(path.abspath(__file__)))

from ai_dirscan import (
    Scanner, LearningStore, Checkpoint, load_wordlist,
    Display, STOP_EVENT, is_safe_path_token, install_signal_handler,
    COLOR_AVAILABLE, Fore, Style, TOOL_VERSION,
)
try:
    from argus_triage import TriageSession
except ImportError:
    TriageSession = None

import requests

CONSOLE_TITLE = "ArgusDir Interactive Console"


def color(text, col, use_color):
    if not use_color or not COLOR_AVAILABLE:
        return text
    return f"{col}{text}{Style.RESET_ALL}"


def default_config(args):
    return types.SimpleNamespace(
        timeout=args.timeout, threads=args.threads, no_color=args.no_color,
        insecure=args.insecure, follow_redirects=False, head_first=args.head_first,
        depth=args.depth, delay=args.delay, jitter=0.05, max_rps=args.max_rps,
        retries=1, user_agent=args.user_agent, allow_private=args.allow_private,
        cache_db=None, no_cache=args.no_cache, checkpoint=None, no_resume=False,
    )


class Console:
    ACKS = ("On it.", "Sure.", "Alright.", "Got it.", "Okay.")

    def __init__(self, args):
        self.use_color = (not args.no_color) and COLOR_AVAILABLE
        self.config = default_config(args)
        self.wordlist = load_wordlist(args.list_file, self.use_color)
        self.learning = LearningStore(args.cache_db, enabled=not args.no_cache)
        self.scanner = Scanner(self.config, self.learning, None)
        self.current = None
        self.prepared = {}

    def _rebuild_scanner(self):
        self.scanner.close()
        self.scanner = Scanner(self.config, self.learning, None)
        self.prepared = {}

    def say(self, text):
        print(color("argus > ", Fore.MAGENTA, self.use_color) + text + "\n")

    def _current_results(self):
        if not self.current:
            return []
        prefix = self.current
        return [r for r in self.scanner.results if r.get('url', '').startswith(prefix)]

    def _triage(self):
        if TriageSession is None:
            return None
        return TriageSession(self._current_results(), self.use_color, llm=None)

    def do_scan(self, target):
        target = target.strip() or self.current
        if not target:
            self.say("Give me a target first — 'scan https://example.com'.")
            return
        STOP_EVENT.clear()
        try:
            found = self.scanner.scan(target, list(self.wordlist))
        except ValueError as exc:
            self.say(f"Can't scan that: {exc}")
            return
        except requests.exceptions.RequestException:
            self.say("That target wouldn't respond — it may be down, blocking me, or the wrong URL.")
            return
        base = self.scanner._normalize_url(target)[0]
        self.current = base
        self.prepared.pop(base, None)
        total = len(self._current_results())
        if found:
            self.say(f"{random.choice(self.ACKS)} Scan's done — {found} new on this pass, {total} known on {base}. "
                     "Ask me 'what's critical' or 'what next' when you want my read on them.")
        else:
            self.say(f"Scan finished, nothing new turned up on {base}. "
                     + (f"Still have {total} from before." if total else "Clean, or well-locked-down."))

    def _ensure_prepared(self, target):
        if target in self.prepared:
            return self.prepared[target]
        base, host, fingerprint, cms = self.scanner.prepare_target(target)
        self.prepared[base] = (base, host, fingerprint, cms)
        self.current = base
        return self.prepared[base]

    def do_check(self, token):
        token = token.strip().lstrip('/')
        if not self.current:
            self.say("I need a target before I can poke at a path — run a scan first, or 'scan <url>'.")
            return
        if not is_safe_path_token(token):
            self.say(f"'{token}' isn't a path I'll send — it has characters I don't trust in a URL.")
            return
        try:
            base, host, _fp, _cms = self._ensure_prepared(self.current)
            result = self.scanner.probe(base, host, token)
        except ValueError as exc:
            self.say(f"Couldn't check that: {exc}")
            return
        except requests.exceptions.RequestException:
            self.say(f"No usable response for /{token} — connection failed or timed out.")
            return
        bullet = Display.status_bullet(result['status'], self.use_color)
        if result['is_valid']:
            extra = ""
            if result['info'].get('directory_listing'):
                extra = " And it's listing the directory contents — worth a look."
            elif result['info'].get('cms'):
                extra = f" Looks like {result['info']['cms']} under the hood."
            self.say(f"{bullet} {result['url']} — that's a real hit.{extra} I've added it to the findings.")
        else:
            reason = "looks like the server's not-found baseline" if result['status'] in (200, 404) else "nothing that reads as a genuine resource"
            self.say(f"{bullet} {result['url']} — {reason}, so I'm not counting it.")

    def do_set(self, body):
        parts = body.split()
        if len(parts) < 2:
            self.say("Tell me what to set, e.g. 'set threads 20', 'set depth 2', 'set head-first on'.")
            return
        key, value = parts[0].lower().replace('-', '_'), parts[1]
        changed = True
        try:
            if key == 'threads':
                self.config.threads = max(1, int(value))
            elif key == 'depth':
                self.config.depth = max(0, int(value))
            elif key == 'timeout':
                self.config.timeout = max(1, int(value))
            elif key in ('delay',):
                self.config.delay = max(0.0, float(value))
            elif key in ('rps', 'max_rps'):
                self.config.max_rps = float(value) if float(value) > 0 else None
            elif key in ('head_first', 'headfirst'):
                self.config.head_first = value.lower() in ('on', 'true', 'yes', '1')
            elif key in ('wordlist', 'list'):
                self.wordlist = load_wordlist(value, self.use_color)
                self.say(f"Wordlist swapped — {len(self.wordlist)} entries loaded.")
                return
            else:
                changed = False
        except ValueError:
            self.say(f"'{value}' isn't a value I can use for {parts[0]}.")
            return
        if not changed:
            self.say(f"I don't have a setting called '{parts[0]}'. Try threads, depth, timeout, delay, rps, head-first, or wordlist.")
            return
        self._rebuild_scanner()
        self.say(f"Done — {parts[0]} is now {value}. (Fresh engine; next scan recalibrates.)")

    def do_config(self):
        c = self.config
        lines = [
            f"  target:     {self.current or '(none yet)'}",
            f"  threads:    {c.threads}",
            f"  depth:      {c.depth} {'(recursive)' if c.depth else '(off)'}",
            f"  head-first: {'on' if c.head_first else 'off'}",
            f"  timeout:    {c.timeout}s   delay: {c.delay}s   rps cap: {c.max_rps or 'none'}",
            f"  wordlist:   {len(self.wordlist)} entries",
        ]
        self.say("Current setup:\n" + "\n".join(lines))

    def do_export(self, body):
        parts = body.split()
        if not parts:
            self.say("Where should I write them? 'export results.json' (or .csv).")
            return
        out = parts[0]
        fmt = 'csv' if out.lower().endswith('.csv') else 'json'
        if self.scanner.export(out, fmt):
            self.say(f"Written to {out}. You can reopen it later with argus_triage.py if you want to talk it over offline.")
        else:
            self.say("Nothing to export yet, or I couldn't write that file.")

    def do_help(self):
        self.say(
            "I'm an active scanner you can just talk to. Things you can say:\n"
            "  scan <url>            run a full discovery pass on a target\n"
            "  check <path>          probe one path live and tell you if it's real\n"
            "  set <opt> <value>     threads, depth, timeout, delay, rps, head-first, wordlist\n"
            "  config                show the current setup\n"
            "  what's critical / explain <path> / what next   my read on the findings\n"
            "  results / export <file>                        list or save findings\n"
            "  quit"
        )

    def route(self, text):
        raw = text.strip()
        if not raw:
            return True
        low = raw.lower()
        if low in ('quit', 'exit', 'bye', 'q', ':q'):
            return False
        if low in ('help', '?', 'commands'):
            self.do_help()
            return True
        if low in ('config', 'settings', 'setup', 'status'):
            self.do_config()
            return True

        m = re.match(r'(?:scan|run|go scan|hit)\s+(\S.*)', low)
        if m:
            self.do_scan(raw[m.start(1):].strip())
            return True
        if low in ('scan', 'rescan', 'scan again'):
            self.do_scan('')
            return True

        m = re.match(r'(?:check|verify|test|probe|try|hit)\s+(\S.*)', low)
        if m:
            self.do_check(raw[m.start(1):].strip())
            return True

        m = re.match(r'set\s+(.+)', low)
        if m:
            self.do_set(raw[m.start(1):].strip())
            return True
        m = re.match(r'(?:use|with)\s+(\d+)\s+threads?', low)
        if m:
            self.do_set(f"threads {m.group(1)}")
            return True
        m = re.match(r'(?:depth|go)\s+(\d+)\s*(?:deep|levels?)?', low)
        if m:
            self.do_set(f"depth {m.group(1)}")
            return True

        m = re.match(r'export\s+(.+)', low)
        if m:
            self.do_export(raw[m.start(1):].strip())
            return True

        if low in ('results', 'findings', 'list', 'show results', 'recap'):
            session = self._triage()
            if session is None:
                self.say("I can scan and check paths, but reading findings needs argus_triage.py in the same folder as this console.")
                return True
            self.say(session.list_all() or "No findings yet — run a scan.")
            return True

        if re.match(r'https?://', low) or re.match(r'^[\w.-]+\.[a-z]{2,}', low):
            self.say(f"Want me to scan {raw}? Say 'scan {raw}' and I'll go.")
            return True

        if not self._current_results():
            self.say("Nothing scanned yet, so I've got nothing to reason about. Point me at a target with 'scan <url>'.")
            return True
        session = self._triage()
        if session is None:
            self.say("Scan and check work fine, but talking through findings needs argus_triage.py in the same folder as this console.")
            return True
        self.say(session.answer(raw) or "")
        return True

    def run(self):
        print(color(f"{CONSOLE_TITLE} (engine v{TOOL_VERSION})", Fore.CYAN + Style.BRIGHT, self.use_color))
        print(color("[!] Only point this at systems you own or are authorized to test.", Fore.YELLOW, self.use_color))
        print("I can scan a target and talk through what I find. Say 'scan <url>', or 'help'.\n")
        while True:
            try:
                text = input(color("you > ", Fore.GREEN, self.use_color))
            except (EOFError, KeyboardInterrupt):
                print("\nWrapping up. Good hunting.")
                break
            try:
                if not self.route(text):
                    print("Later.")
                    break
            except KeyboardInterrupt:
                STOP_EVENT.set()
                print(color("\n[!] stopped the current action.", Fore.YELLOW, self.use_color))
                STOP_EVENT.clear()
        self.close()

    def close(self):
        self.scanner.close()
        self.learning.close()


def build_parser():
    p = argparse.ArgumentParser(
        prog='argus_console.py',
        description=f"{CONSOLE_TITLE} - drive the live scanner by conversation",
        epilog="Only scan systems you own or are explicitly authorized to test.",
    )
    p.add_argument('-u', '--url', dest='url', help='optional target to scan on startup')
    p.add_argument('-l', '--list', dest='list_file', help='wordlist file')
    p.add_argument('-t', '--threads', type=int, default=10)
    p.add_argument('--timeout', type=int, default=8)
    p.add_argument('--delay', type=float, default=0.0)
    p.add_argument('--max-rps', type=float, default=None)
    p.add_argument('--depth', type=int, default=0)
    p.add_argument('--head-first', dest='head_first', action='store_true')
    p.add_argument('--user-agent', dest='user_agent', default=None)
    p.add_argument('--insecure', action='store_true')
    p.add_argument('--allow-private', action='store_true')
    p.add_argument('--no-color', action='store_true')
    p.add_argument('--no-cache', action='store_true')
    p.add_argument('--cache-db', dest='cache_db', default=None)
    return p


def main():
    args = build_parser().parse_args()
    install_signal_handler()
    console = Console(args)
    if args.url:
        console.do_scan(args.url)
    console.run()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
