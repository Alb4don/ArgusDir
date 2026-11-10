#!/usr/bin/env python3

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
import queue
import random
import re
import signal
import socket
import statistics
import string
import sqlite3
import sys
import threading
import time
import unicodedata
from collections import Counter, defaultdict
from os import path
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

TOOL_NAME = "ArgusDir"
TOOL_TITLE = "ArgusDir - Adaptive Content Discovery Scanner"
TOOL_VERSION = "2.1.0"

PATH_SAFE_PATTERN = re.compile(r'^[A-Za-z0-9._~](?:[A-Za-z0-9/_\-.~%]{0,510})?$')
HOSTNAME_PATTERN = re.compile(r'^[A-Za-z0-9.\-:_\[\]]+$')
CONTROL_CHARS = ('\r', '\n', '\t', '\x00')

STOP_EVENT = threading.Event()


def is_safe_path_token(candidate):
    if not isinstance(candidate, str):
        return False
    candidate = candidate.strip()
    if not candidate or len(candidate) > 512:
        return False
    if any(ch in candidate for ch in CONTROL_CHARS) or ' ' in candidate:
        return False
    if '..' in candidate:
        return False
    return bool(PATH_SAFE_PATTERN.match(candidate))


def sanitize_for_log(text, limit=200):
    if not isinstance(text, str):
        text = str(text)
    cleaned = ''.join(ch for ch in text if ch in string.printable and ch not in ('\r', '\n', '\t'))
    return cleaned[:limit]


def content_fingerprint(raw_bytes):
    return hashlib.blake2b(raw_bytes, digest_size=16).hexdigest()


def atomic_write_json(filepath, payload):
    tmp = f"{filepath}.{os.getpid()}.tmp"
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, ensure_ascii=False)
    os.replace(tmp, filepath)


class Display:
    WIDTH = 64

    @staticmethod
    def _wrap(text, color, use_color):
        if not use_color or not COLOR_AVAILABLE:
            return text
        return f"{color}{text}{Style.RESET_ALL}"

    @staticmethod
    def banner(use_color=True):
        art = [
            "    _                        ____  _",
            "   / \\   _ __ __ _ _   _ ___|  _ \\(_)_ __",
            "  / _ \\ | '__/ _` | | | / __| | | | | '__|",
            " / ___ \\| | | (_| | |_| \\__ \\ |_| | | |",
            "/_/   \\_\\_|  \\__, |\\__,_|___/____/|_|_|",
            f"            |___/   {TOOL_TITLE}",
            f"                    v{TOOL_VERSION}",
        ]
        return Display._wrap('\n'.join(art), Fore.CYAN + Style.BRIGHT, use_color)

    @staticmethod
    def section(title, use_color=True):
        label = f" {title} "
        fill = max(0, Display.WIDTH - len(label) - 3)
        return Display._wrap(f"+--{label}" + '-' * fill, Fore.CYAN, use_color)

    @staticmethod
    def status_bullet(status_code, use_color=True):
        if status_code == 200:
            color = Fore.GREEN
        elif status_code in (401, 403):
            color = Fore.YELLOW
        elif status_code in (301, 302, 303, 307, 308):
            color = Fore.CYAN
        elif status_code >= 500:
            color = Fore.RED
        else:
            color = Fore.MAGENTA
        return Display._wrap(f"[{status_code}]", color, use_color)

    @staticmethod
    def progress_bar(done, total, width=30, use_color=True):
        total = max(total, 1)
        ratio = min(1.0, done / total)
        filled = int(width * ratio)
        bar = '#' * filled + '.' * (width - filled)
        return Display._wrap(f"[{bar}] {done}/{total} ({ratio * 100:.0f}%)", Fore.CYAN, use_color)

    @staticmethod
    def info(text, use_color=True):
        return Display._wrap(f"[*] {text}", Fore.CYAN, use_color)

    @staticmethod
    def good(text, use_color=True):
        return Display._wrap(f"[+] {text}", Fore.GREEN, use_color)

    @staticmethod
    def warn(text, use_color=True):
        return Display._wrap(f"[!] {text}", Fore.YELLOW, use_color)

    @staticmethod
    def error(text, use_color=True):
        return Display._wrap(f"[x] {text}", Fore.RED, use_color)


class UCBBandit:
    def __init__(self, arms, exploration=math.sqrt(2)):
        self.c = exploration
        self.pulls = {a: 0 for a in arms}
        self.rewards = {a: 0.0 for a in arms}
        self.total_pulls = 0
        self.lock = threading.Lock()

    def order_arms(self, arms):
        with self.lock:
            scores = {}
            for a in arms:
                if a not in self.pulls:
                    self.pulls[a] = 0
                    self.rewards[a] = 0.0
                if self.pulls[a] == 0:
                    scores[a] = float('inf')
                else:
                    mean = self.rewards[a] / self.pulls[a]
                    bonus = self.c * math.sqrt(math.log(max(self.total_pulls, 1)) / self.pulls[a])
                    scores[a] = mean + bonus
            return sorted(arms, key=lambda a: scores[a], reverse=True)

    def update(self, arm, reward):
        with self.lock:
            if arm not in self.pulls:
                self.pulls[arm] = 0
                self.rewards[arm] = 0.0
            self.pulls[arm] += 1
            self.rewards[arm] += float(reward)
            self.total_pulls += 1

    def stats(self):
        with self.lock:
            return {
                arm: (pulls, (self.rewards[arm] / pulls) if pulls else 0.0)
                for arm, pulls in self.pulls.items()
            }


class RateController:
    def __init__(self, base_delay=0.0, jitter=0.05, max_delay=2.0, max_rps=None):
        self.base_delay = max(0.0, base_delay)
        self.jitter = max(0.0, jitter)
        self.max_delay = max_delay
        self.min_interval = (1.0 / max_rps) if (max_rps and max_rps > 0) else 0.0
        self.lock = threading.Lock()
        self.next_slot = 0.0
        self.host_backoff = defaultdict(float)
        self.recent = defaultdict(list)

    def register_result(self, host, ok, throttled):
        with self.lock:
            window = self.recent[host]
            window.append(1 if ok else 0)
            if len(window) > 20:
                window.pop(0)
            if throttled:
                self.host_backoff[host] = min(self.max_delay, max(0.25, (self.host_backoff[host] or 0.25) * 1.7))
            else:
                rate = (sum(window) / len(window)) if window else 1.0
                if rate > 0.8:
                    self.host_backoff[host] = max(0.0, self.host_backoff[host] * 0.8)

    def wait(self, host):
        with self.lock:
            now = time.monotonic()
            if self.min_interval > 0.0:
                slot = max(now, self.next_slot)
                self.next_slot = slot + self.min_interval
                gate_wait = slot - now
            else:
                gate_wait = 0.0
            delay = self.base_delay + self.host_backoff.get(host, 0.0)
        total = gate_wait + delay + random.uniform(0.0, self.jitter)
        if total > 0:
            STOP_EVENT.wait(total)


class ResponseBaseline:
    def __init__(self):
        self.lock = threading.Lock()
        self.hosts = {}

    def calibrate(self, host, samples):
        with self.lock:
            lengths_by_status = defaultdict(list)
            hashes = set()
            texts = []
            statuses = []
            for s in samples:
                statuses.append(s['status'])
                lengths_by_status[s['status']].append(s['length'])
                hashes.add(s['hash'])
                if s.get('text'):
                    texts.append(s['text'])
            self.hosts[host] = {
                'modal_status': Counter(statuses).most_common(1)[0][0] if statuses else None,
                'lengths_by_status': {k: list(v) for k, v in lengths_by_status.items()},
                'hashes': hashes,
                'texts': texts,
                'calibrated': bool(samples),
            }

    def is_calibrated(self, host):
        with self.lock:
            data = self.hosts.get(host)
            return bool(data and data.get('calibrated'))

    def classify(self, host, status, length, chash, text):
        with self.lock:
            data = self.hosts.get(host)
            if not data:
                return 'unknown', 0.0
            if chash in data['hashes']:
                return 'baseline', 1.0
            lengths = data['lengths_by_status'].get(status)
            texts = list(data['texts'])
            modal = data['modal_status']

        if lengths:
            if len(lengths) >= 3:
                try:
                    mean = statistics.mean(lengths)
                    stdev = statistics.stdev(lengths)
                except statistics.StatisticsError:
                    mean, stdev = (lengths[0], 0.0)
                if stdev > 0:
                    if abs(length - mean) / stdev < 1.0:
                        return 'baseline', 0.9
                elif length == mean:
                    return 'baseline', 0.95
            else:
                closest = min(lengths, key=lambda x: abs(x - length))
                if closest > 0 and abs(closest - length) / closest < 0.02:
                    return 'baseline', 0.85

        if status == modal and texts and text:
            best = 0.0
            for sample in texts[:3]:
                best = max(best, difflib_ratio(sample, text))
            if best > 0.92:
                return 'baseline', best
            if best > 0.80:
                return 'likely_fp', best

        return 'distinct', 0.0


def difflib_ratio(a, b):
    import difflib
    return difflib.SequenceMatcher(None, a, b).ratio()


class LearningStore:
    def __init__(self, db_path=None, enabled=True):
        self.enabled = enabled
        self.available = False
        self.lock = threading.Lock()
        self.conn = None
        if not enabled:
            return
        if db_path is None:
            db_path = path.join(path.expanduser('~'), '.argusdir', 'learning.db')
        try:
            parent = path.dirname(db_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
            with self.lock:
                self.conn.execute('PRAGMA journal_mode=WAL')
                self.conn.execute('PRAGMA synchronous=NORMAL')
                self.conn.execute('''CREATE TABLE IF NOT EXISTS path_stats (
                    fingerprint TEXT NOT NULL,
                    path TEXT NOT NULL,
                    hits INTEGER DEFAULT 0,
                    attempts INTEGER DEFAULT 0,
                    last_seen REAL,
                    PRIMARY KEY (fingerprint, path)
                )''')
                self.conn.commit()
            self.available = True
        except (sqlite3.Error, OSError):
            self.available = False

    def prioritized_paths(self, fingerprint, limit=25, half_life_days=30.0):
        if not self.available or not fingerprint:
            return []
        now = time.time()
        decay = math.log(2) / (half_life_days * 86400.0)
        with self.lock:
            try:
                cur = self.conn.execute(
                    'SELECT path, hits, attempts, last_seen FROM path_stats '
                    'WHERE fingerprint = ? AND hits > 0 ORDER BY hits DESC, last_seen DESC LIMIT ?',
                    (fingerprint, limit * 3)
                )
                rows = cur.fetchall()
            except sqlite3.Error:
                return []
        scored = []
        for p, hits, attempts, last_seen in rows:
            if not is_safe_path_token(p):
                continue
            posterior = (hits + 1.0) / (attempts + 2.0)
            age = max(0.0, now - (last_seen or now))
            recency = math.exp(-decay * age)
            scored.append((posterior * recency, p))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in scored[:limit]]

    def record_batch(self, fingerprint, attempts_map, hits_set):
        if not self.available or not fingerprint:
            return
        now = time.time()
        rows = []
        for p, count in attempts_map.items():
            if not is_safe_path_token(p):
                continue
            rows.append((fingerprint, p, 1 if p in hits_set else 0, count, now))
        if not rows:
            return
        with self.lock:
            try:
                self.conn.executemany('''
                    INSERT INTO path_stats (fingerprint, path, hits, attempts, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(fingerprint, path) DO UPDATE SET
                        hits = hits + excluded.hits,
                        attempts = attempts + excluded.attempts,
                        last_seen = excluded.last_seen
                ''', rows)
                self.conn.commit()
            except sqlite3.Error:
                pass

    def close(self):
        if self.available and self.conn is not None:
            with self.lock:
                try:
                    self.conn.close()
                except sqlite3.Error:
                    pass


class Checkpoint:
    def __init__(self, filepath, flush_every=100):
        self.filepath = filepath
        self.flush_every = max(1, flush_every)
        self.lock = threading.Lock()
        self.data = {}
        self.counter = 0

    def load(self):
        try:
            with open(self.filepath, 'r', encoding='utf-8') as fh:
                raw = json.load(fh)
            restored = {}
            for target, state in raw.items():
                restored[target] = {
                    'completed': set(state.get('completed', [])),
                    'results': list(state.get('results', [])),
                }
            with self.lock:
                self.data = restored
        except (OSError, ValueError):
            with self.lock:
                self.data = {}

    def begin(self, target):
        with self.lock:
            self.data.setdefault(target, {'completed': set(), 'results': []})

    def state(self, target):
        with self.lock:
            state = self.data.get(target, {'completed': set(), 'results': []})
            return set(state['completed']), list(state['results'])

    def mark(self, target, token):
        flush = False
        with self.lock:
            self.data.setdefault(target, {'completed': set(), 'results': []})
            self.data[target]['completed'].add(token)
            self.counter += 1
            if self.counter % self.flush_every == 0:
                flush = True
        if flush:
            self.flush()

    def add_result(self, target, result):
        with self.lock:
            self.data.setdefault(target, {'completed': set(), 'results': []})
            self.data[target]['results'].append(result)

    def flush(self):
        with self.lock:
            payload = {
                target: {'completed': sorted(state['completed']), 'results': state['results']}
                for target, state in self.data.items()
            }
        try:
            atomic_write_json(self.filepath, payload)
        except OSError:
            pass


class Scanner:
    DIRECTORY_INDICATORS = (
        'index of /', 'directory listing', 'parent directory',
        '<title>index of', 'directory browsing',
    )
    CMS_SIGNATURES = {
        'wordpress': ('wp-content', 'wp-includes', 'wp-admin'),
        'drupal': ('drupal.settings', 'sites/default/files', '/core/misc/drupal'),
        'joomla': ('/media/jui/', 'com_content', 'joomla'),
        'django': ('csrfmiddlewaretoken', '__admin_media_prefix__'),
        'laravel': ('laravel_session', 'vendor/laravel'),
    }
    VALID_CODES = frozenset([200, 201, 202, 204, 206, 301, 302, 303, 307, 308, 401, 403, 405, 500])
    THROTTLE_CODES = frozenset([429, 503])
    HEAD_UNSUPPORTED = frozenset([405, 501])
    EXTENSIONS = ('.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.txt', '.bak', '.old', '.env', '.zip', '.sql', '.log')
    COMMON_SUBPATHS = (
        'admin', 'api', 'assets', 'backup', 'config', 'data', 'dev', 'docs',
        'images', 'includes', 'js', 'css', 'media', 'private', 'public',
        'scripts', 'temp', 'test', 'uploads', 'vendor', 'logs', 'internal',
    )

    def __init__(self, args, learning_store, checkpoint=None):
        self.args = args
        self.timeout = args.timeout
        self.threads = max(1, args.threads)
        self.use_color = (not args.no_color) and COLOR_AVAILABLE
        self.verify_tls = not args.insecure
        self.follow_redirects = args.follow_redirects
        self.head_first = args.head_first
        self.max_depth = max(0, args.depth)
        self.session = self._build_session(args)
        self.learning = learning_store
        self.checkpoint = checkpoint
        self.baseline = ResponseBaseline()
        self.rate = RateController(base_delay=args.delay, jitter=args.jitter, max_rps=args.max_rps)
        self.bandit = UCBBandit(['base', 'extension', 'suffix', 'pattern'])
        self.lock = threading.Lock()
        self.results = []
        self.seen_results = set()
        self._head_supported = {}
        self._scan_wordlist = []

    def _build_session(self, args):
        session = requests.Session()
        try:
            retry = Retry(
                total=max(0, args.retries), backoff_factor=0.3,
                status_forcelist=[502, 503, 504],
                allowed_methods=frozenset(['GET', 'HEAD']),
                respect_retry_after_header=True,
            )
        except TypeError:
            retry = Retry(
                total=max(0, args.retries), backoff_factor=0.3,
                status_forcelist=[502, 503, 504],
                method_whitelist=frozenset(['GET', 'HEAD']),
            )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=self.threads * 2, pool_maxsize=self.threads * 2)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        ua = args.user_agent or (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/124.0 Safari/537.36'
        )
        session.headers.update({
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        if not self.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return session

    def _normalize_url(self, url):
        if not isinstance(url, str):
            raise ValueError("target must be a string")
        normalized = unicodedata.normalize('NFKC', url.strip())
        if not normalized or any(ch in normalized for ch in CONTROL_CHARS):
            raise ValueError("target contains invalid characters")
        if not normalized.startswith(('http://', 'https://')):
            normalized = f"http://{normalized}"
        parsed = urlparse(normalized)
        host = parsed.netloc.split('@')[-1]
        if not host or not HOSTNAME_PATTERN.match(host):
            raise ValueError("invalid target hostname")
        return normalized.rstrip('/'), parsed.netloc

    def _private_target(self, netloc):
        hostname = netloc.split('@')[-1].split(':')[0].strip('[]')
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            try:
                resolved = socket.getaddrinfo(hostname, None)[0][4][0]
                ip = ipaddress.ip_address(resolved)
                return ip.is_private or ip.is_loopback or ip.is_link_local
            except (socket.gaierror, ValueError, IndexError):
                return False

    def _get(self, url):
        return self.session.get(url, timeout=self.timeout, allow_redirects=self.follow_redirects, verify=self.verify_tls)

    def _fetch(self, url, host):
        if self.head_first and self._head_supported.get(host, True):
            head = self.session.head(url, timeout=self.timeout, allow_redirects=self.follow_redirects, verify=self.verify_tls)
            if head.status_code in self.HEAD_UNSUPPORTED:
                self._head_supported[host] = False
            elif head.status_code == 404:
                return head
            else:
                return self._get(url)
        return self._get(url)

    def _random_token(self, n=18):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def _calibrate(self, base_url, host):
        samples = []
        probes = [self._random_token(), f"{self._random_token()}.{self._random_token(4)}", f"{self._random_token()}/{self._random_token(6)}"]
        for probe in probes:
            if STOP_EVENT.is_set():
                break
            try:
                resp = self._get(f"{base_url}/{probe}")
                body = resp.content or b''
                samples.append({
                    'status': resp.status_code, 'length': len(body),
                    'hash': content_fingerprint(body),
                    'text': (resp.text[:800] if resp.text else ''),
                })
            except requests.exceptions.RequestException:
                continue
        self.baseline.calibrate(host, samples)

    def _fingerprint_stack(self, base_url, host):
        try:
            resp = self._get(base_url)
        except requests.exceptions.RequestException:
            return None, None
        server = (resp.headers.get('server', '') or '').strip().lower()
        powered = (resp.headers.get('x-powered-by', '') or '').strip().lower()
        body = (resp.text or '').lower()
        cms = ''
        for name, sigs in self.CMS_SIGNATURES.items():
            if any(sig in body for sig in sigs):
                cms = name
                break
        source = f"server:{server}|powered:{powered}|cms:{cms}"
        if not (server or powered or cms):
            return None, cms or None
        return hashlib.blake2b(source.encode('utf-8'), digest_size=12).hexdigest(), (cms or None)

    def _analyze(self, resp):
        lower = (resp.text or '').lower()
        info = {
            'directory_listing': any(ind in lower for ind in self.DIRECTORY_INDICATORS),
            'content_type': resp.headers.get('content-type', ''),
            'headers': {}, 'cms': None,
        }
        for header in ('x-powered-by', 'server', 'x-aspnet-version', 'x-generator'):
            if header in resp.headers:
                info['headers'][header] = sanitize_for_log(resp.headers[header], 120)
        for name, sigs in self.CMS_SIGNATURES.items():
            if any(sig in lower for sig in sigs):
                info['cms'] = name
                break
        return info

    def _evaluate(self, resp, host):
        status = resp.status_code
        body = resp.content or b''
        length = len(body)
        chash = content_fingerprint(body)
        text = resp.text[:800] if resp.text else ''

        if status == 404 or status in self.THROTTLE_CODES:
            return False, 0.0
        label, _ = self.baseline.classify(host, status, length, chash, text)
        if label in ('baseline', 'likely_fp'):
            return False, 0.2
        if status in self.VALID_CODES:
            if status == 200 and length < 1200:
                low = (resp.text or '').lower()
                if any(tok in low for tok in ('404', 'not found', 'page not found', 'file not found', 'does not exist')):
                    return False, 0.2
            return True, 1.0
        return False, 0.1

    def _is_directory_hit(self, resp, directory, info):
        if info.get('directory_listing'):
            return True
        location = (resp.headers.get('Location', '') or '').strip()
        if resp.status_code in (301, 302, 307, 308) and location.endswith('/'):
            return True
        if resp.status_code in (200, 204) and '.' not in directory.rstrip('/').split('/')[-1]:
            return True
        return False

    def _generate_candidates(self, discovered):
        seen = set()
        tagged = []

        def add(items, arm):
            for it in items:
                if it not in seen and is_safe_path_token(it):
                    seen.add(it)
                    tagged.append((it, arm))

        for d in discovered:
            for part in d.split('/'):
                if len(part) > 2:
                    add([f"{part}_old", f"{part}_bak", f"{part}.bak", f"{part}2", f"old_{part}"], 'suffix')
                    add([f"{part}{ext}" for ext in self.EXTENSIONS], 'extension')
            base = d.strip('/')
            add([f"{base}/{sub}" for sub in self.COMMON_SUBPATHS], 'pattern')
        return tagged

    def _order_candidates(self, tagged, limit):
        arms = sorted({arm for _, arm in tagged})
        if not arms:
            return []
        order = self.bandit.order_arms(arms)
        buckets = defaultdict(list)
        for cand, arm in tagged:
            buckets[arm].append(cand)
        ordered = []
        cursors = {a: 0 for a in order}
        while len(ordered) < limit:
            progressed = False
            for arm in order:
                idx = cursors[arm]
                if idx < len(buckets[arm]):
                    ordered.append((buckets[arm][idx], arm))
                    cursors[arm] += 1
                    progressed = True
                    if len(ordered) >= limit:
                        break
            if not progressed:
                break
        return ordered

    def _record_result(self, target, url, status, info, arm):
        with self.lock:
            if url in self.seen_results:
                return False, None
            self.seen_results.add(url)
            record = {
                'url': url, 'status': status,
                'content_type': info.get('content_type', ''),
                'directory_listing': info.get('directory_listing', False),
                'cms': info.get('cms'), 'strategy': arm,
            }
            self.results.append(record)
        return True, record

    def _print_hit(self, url, status, info, prefix=''):
        print(f"{prefix}{Display.status_bullet(status, self.use_color)} {url}")
        if info.get('directory_listing'):
            print(Display.warn("      directory listing exposed", self.use_color))
        if info.get('cms'):
            print(Display.info(f"      stack: {info['cms']}", self.use_color))
        if info.get('headers'):
            print(f"      headers: {info['headers']}")

    def _enqueue_recursion(self, task_q, directory, depth, seen_paths, extend_lock, max_extend, progress):
        base = directory.strip('/')
        added = 0
        with extend_lock:
            for entry in self._scan_wordlist:
                if len(seen_paths) >= max_extend:
                    break
                token = f"{base}/{entry}"
                if token not in seen_paths and is_safe_path_token(token):
                    task_q.put((token, 'recurse', depth + 1))
                    added += 1
        if added:
            with progress['lock']:
                progress['total'] += added
            print(Display.info(f"      descending into {base}/ ({added} paths, depth {depth + 1})", self.use_color))

    def _worker(self, task_q, base_url, host, fingerprint, attempts_map, hits_set,
                extend_lock, seen_paths, max_extend, progress):
        while not STOP_EVENT.is_set():
            try:
                directory, arm, depth = task_q.get_nowait()
            except queue.Empty:
                return
            processed = False
            try:
                if not is_safe_path_token(directory):
                    continue
                with extend_lock:
                    if directory in seen_paths:
                        continue
                    seen_paths.add(directory)
                with self.lock:
                    attempts_map[directory] += 1

                target = f"{base_url}/{directory.lstrip('/')}"
                self.rate.wait(host)
                try:
                    resp = self._fetch(target, host)
                except requests.exceptions.RequestException:
                    self.rate.register_result(host, ok=False, throttled=False)
                    self.bandit.update(arm, 0.0)
                    processed = True
                    continue

                throttled = resp.status_code in self.THROTTLE_CODES
                is_valid, reward = self._evaluate(resp, host)
                self.rate.register_result(host, ok=not throttled, throttled=throttled)
                self.bandit.update(arm, reward)
                processed = True

                if is_valid:
                    info = self._analyze(resp)
                    created, record = self._record_result(base_url, resp.url, resp.status_code, info, arm)
                    if created:
                        self._print_hit(resp.url, resp.status_code, info)
                        with self.lock:
                            hits_set.add(directory)
                        if self.checkpoint and record:
                            self.checkpoint.add_result(base_url, record)
                        if self.follow_redirects:
                            self._extend_from_links(resp, task_q, seen_paths, extend_lock, max_extend, progress)
                        if self.max_depth > 0 and depth < self.max_depth and self._is_directory_hit(resp, directory, info):
                            self._enqueue_recursion(task_q, directory, depth, seen_paths, extend_lock, max_extend, progress)
            finally:
                if processed and self.checkpoint:
                    self.checkpoint.mark(base_url, directory)
                with progress['lock']:
                    progress['done'] += 1
                    done = progress['done']
                    decile = (done * 10) // max(progress['total'], 1)
                    show = decile > progress['decile'] and done <= progress['total']
                    if show:
                        progress['decile'] = decile
                if show:
                    print(Display.progress_bar(min(done, progress['total']), progress['total'], use_color=self.use_color))
                task_q.task_done()

    def _extend_from_links(self, resp, task_q, seen_paths, extend_lock, max_extend, progress):
        try:
            hrefs = re.findall(r'(?:href|src)=["\']([^"\']{1,256})["\']', resp.text or '', re.IGNORECASE)
        except (TypeError, re.error):
            return
        added = 0
        with extend_lock:
            for link in hrefs:
                if added >= 10 or len(seen_paths) >= max_extend:
                    break
                if link.startswith('/') and not link.startswith('//'):
                    token = link.strip('/').split('?')[0].split('#')[0]
                    if token and token not in seen_paths and is_safe_path_token(token):
                        task_q.put((token, 'crawl', 0))
                        added += 1
        if added:
            with progress['lock']:
                progress['total'] += added

    def scan(self, url, wordlist):
        base_url, host = self._normalize_url(url)
        if self._private_target(host) and not self.args.allow_private:
            raise ValueError(f"{host} resolves to a private/internal address; pass --allow-private to scan it")

        self._scan_wordlist = [w for w in wordlist if is_safe_path_token(w)]

        print(Display.section(f"target: {host}", self.use_color))
        mode_bits = [f"threads {self.threads}"]
        if self.head_first:
            mode_bits.append("head-first")
        if self.max_depth:
            mode_bits.append(f"recursive depth {self.max_depth}")
        print(Display.info(f"wordlist {len(self._scan_wordlist)} | " + ' | '.join(mode_bits), self.use_color))

        self._calibrate(base_url, host)
        if not self.baseline.is_calibrated(host):
            print(Display.warn("baseline calibration failed; false-positive filtering reduced", self.use_color))
        fingerprint, cms = self._fingerprint_stack(base_url, host)
        if cms:
            print(Display.info(f"detected stack: {cms}", self.use_color))

        completed = set()
        if self.checkpoint:
            self.checkpoint.begin(base_url)
            completed, prior = self.checkpoint.state(base_url)
            with self.lock:
                for record in prior:
                    if record.get('url') and record['url'] not in self.seen_results:
                        self.seen_results.add(record['url'])
                        self.results.append(record)
            if completed:
                print(Display.info(f"resume: skipping {len(completed)} previously tested paths", self.use_color))

        task_q = queue.Queue()
        queued = set()

        if self.learning and fingerprint:
            learned = [p for p in self.learning.prioritized_paths(fingerprint, limit=25) if p not in queued and p not in completed]
            if learned:
                print(Display.info(f"learning store: {len(learned)} high-probability paths for this stack", self.use_color))
                for p in learned:
                    task_q.put((p, 'learned', 0))
                    queued.add(p)

        for entry in self._scan_wordlist:
            if entry not in queued and entry not in completed:
                task_q.put((entry, 'base', 0))
                queued.add(entry)

        seen_paths = set(completed)
        attempts_map = defaultdict(int)
        hits_set = set()
        extend_lock = threading.Lock()
        max_extend = len(queued) + len(completed) + 5000
        progress = {'done': 0, 'decile': 0, 'total': task_q.qsize(), 'lock': threading.Lock()}

        self._run_pool(task_q, base_url, host, fingerprint, attempts_map, hits_set, extend_lock, seen_paths, max_extend, progress)

        discovered = sorted(hits_set)
        if discovered and not STOP_EVENT.is_set():
            self._adaptive_pass(base_url, host, fingerprint, discovered, attempts_map, hits_set)

        if self.learning and fingerprint:
            self.learning.record_batch(fingerprint, attempts_map, hits_set)
        if self.checkpoint:
            self.checkpoint.flush()

        return len(hits_set)

    def _run_pool(self, task_q, base_url, host, fingerprint, attempts_map, hits_set, extend_lock, seen_paths, max_extend, progress):
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(
                target=self._worker,
                args=(task_q, base_url, host, fingerprint, attempts_map, hits_set, extend_lock, seen_paths, max_extend, progress),
                daemon=True,
            )
            t.start()
            workers.append(t)
        try:
            while any(t.is_alive() for t in workers):
                for t in workers:
                    t.join(timeout=0.2)
                if STOP_EVENT.is_set():
                    break
        except KeyboardInterrupt:
            STOP_EVENT.set()

    def _adaptive_pass(self, base_url, host, fingerprint, discovered, attempts_map, hits_set):
        tagged = self._generate_candidates(discovered)
        ordered = self._order_candidates(tagged, limit=60)
        if not ordered:
            return
        print(Display.section("adaptive pass", self.use_color))
        summary = Counter(arm for _, arm in ordered)
        print(Display.info(f"testing {len(ordered)} generated paths (" + ', '.join(f"{a}:{c}" for a, c in summary.items()) + ")", self.use_color))
        task_q = queue.Queue()
        for cand, arm in ordered:
            task_q.put((cand, arm, 0))
        seen_paths = set()
        extend_lock = threading.Lock()
        progress = {'done': 0, 'decile': 0, 'total': task_q.qsize(), 'lock': threading.Lock()}
        self._run_pool(task_q, base_url, host, fingerprint, attempts_map, hits_set, extend_lock, seen_paths, len(ordered) + 50, progress)

    def prepare_target(self, url):
        base_url, host = self._normalize_url(url)
        if self._private_target(host) and not self.args.allow_private:
            raise ValueError(f"{host} resolves to a private/internal address; pass allow-private to scan it")
        self._calibrate(base_url, host)
        fingerprint, cms = self._fingerprint_stack(base_url, host)
        return base_url, host, fingerprint, cms

    def probe(self, base_url, host, token):
        if not is_safe_path_token(token):
            raise ValueError("unsafe path token")
        target = f"{base_url}/{token.lstrip('/')}"
        self.rate.wait(host)
        resp = self._fetch(target, host)
        is_valid, reward = self._evaluate(resp, host)
        self.bandit.update('manual', reward)
        info = self._analyze(resp) if is_valid else {}
        record = None
        if is_valid:
            created, record = self._record_result(base_url, resp.url, resp.status_code, info, 'manual')
            if not created:
                record = {
                    'url': resp.url, 'status': resp.status_code,
                    'content_type': info.get('content_type', ''),
                    'directory_listing': info.get('directory_listing', False),
                    'cms': info.get('cms'), 'strategy': 'manual',
                }
        return {'status': resp.status_code, 'url': resp.url, 'is_valid': is_valid, 'info': info, 'record': record}

    def export(self, out_path, fmt):
        if not self.results:
            return False
        rows = sorted(self.results, key=lambda r: r['url'])
        try:
            if fmt == 'json':
                with open(out_path, 'w', encoding='utf-8') as fh:
                    json.dump(rows, fh, indent=2, ensure_ascii=False)
            else:
                with open(out_path, 'w', encoding='utf-8', newline='') as fh:
                    writer = csv.DictWriter(fh, fieldnames=['url', 'status', 'content_type', 'directory_listing', 'cms', 'strategy'])
                    writer.writeheader()
                    writer.writerows(rows)
            return True
        except OSError:
            return False

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass


def load_wordlist(list_file_path, use_color):
    default_wordlist = [
        'admin', 'administrator', 'api', 'assets', 'backup', 'cache', 'config',
        'css', 'data', 'db', 'dev', 'docs', 'downloads', 'files', 'images',
        'img', 'includes', 'js', 'logs', 'media', 'private', 'public', 'scripts',
        'static', 'temp', 'test', 'tmp', 'uploads', 'user', 'users', 'var',
        'wp-admin', 'wp-content', 'wp-includes', 'phpmyadmin', 'login',
        'dashboard', 'server-status', '.git', '.env', 'robots.txt', 'sitemap.xml',
    ]
    if not list_file_path:
        print(Display.info(f"using built-in wordlist ({len(default_wordlist)} entries)", use_color))
        return default_wordlist
    if not path.isfile(list_file_path):
        print(Display.warn(f"wordlist not found; using built-in ({len(default_wordlist)} entries)", use_color))
        return default_wordlist
    try:
        with open(list_file_path, 'r', encoding='utf-8', errors='ignore') as fh:
            raw = [line.strip() for line in fh if line.strip() and not line.startswith('#')]
    except OSError:
        print(Display.warn("could not read wordlist; using built-in", use_color))
        return default_wordlist
    clean = [w for w in raw if is_safe_path_token(w)]
    skipped = len(raw) - len(clean)
    print(Display.info(f"loaded {len(clean)} entries from wordlist", use_color))
    if skipped:
        print(Display.warn(f"skipped {skipped} unsafe entries", use_color))
    return clean or default_wordlist


def build_parser():
    p = argparse.ArgumentParser(
        prog='ai_dirscan.py', add_help=True,
        description=f"{TOOL_TITLE} v{TOOL_VERSION} - authorized content discovery for security assessments",
        epilog="Only scan systems you own or are explicitly authorized to test.",
    )
    p.add_argument('-u', '--url', nargs='+', dest='urls', required=True, help='target URL(s)')
    p.add_argument('-l', '--list', dest='list_file', help='path to wordlist file')
    p.add_argument('-t', '--threads', type=int, default=10, help='worker threads (default 10)')
    p.add_argument('--timeout', type=int, default=8, help='request timeout seconds (default 8)')
    p.add_argument('--retries', type=int, default=1, help='transport retries (default 1)')
    p.add_argument('--delay', type=float, default=0.0, help='base per-request delay seconds (default 0)')
    p.add_argument('--jitter', type=float, default=0.05, help='random jitter seconds (default 0.05)')
    p.add_argument('--max-rps', type=float, default=None, help='global requests-per-second cap')
    p.add_argument('--depth', type=int, default=0, help='recursive descent depth cap (default 0 = off)')
    p.add_argument('--head-first', dest='head_first', action='store_true', help='probe with HEAD, GET only on interesting responses')
    p.add_argument('--user-agent', dest='user_agent', help='custom User-Agent string')
    p.add_argument('--follow-redirects', dest='follow_redirects', action='store_true', help='follow redirects and crawl discovered links')
    p.add_argument('--insecure', action='store_true', help='skip TLS verification')
    p.add_argument('--allow-private', action='store_true', help='permit scanning private/internal addresses')
    p.add_argument('--no-color', action='store_true', help='disable colored output')
    p.add_argument('--no-cache', action='store_true', help='disable the persistent learning store')
    p.add_argument('--cache-db', dest='cache_db', default=None, help='learning store path')
    p.add_argument('--checkpoint', dest='checkpoint', default=None, help='checkpoint file; resumes automatically if it exists')
    p.add_argument('--no-resume', dest='no_resume', action='store_true', help='ignore existing checkpoint state')
    p.add_argument('-o', '--output', dest='output', help='write results to file')
    p.add_argument('--format', dest='fmt', choices=['json', 'csv'], default='json', help='output format (default json)')
    return p


def install_signal_handler():
    def handler(_signum, _frame):
        if not STOP_EVENT.is_set():
            print("\n" + Display.warn("interrupt received; finishing in-flight requests...", True))
            STOP_EVENT.set()
        else:
            raise SystemExit(130)
    try:
        signal.signal(signal.SIGINT, handler)
    except (ValueError, OSError):
        pass


def main():
    args = build_parser().parse_args()
    use_color = (not args.no_color) and COLOR_AVAILABLE
    print(Display.banner(use_color))

    if args.threads < 1:
        print(Display.error("--threads must be at least 1", use_color))
        return 2
    if args.timeout < 1:
        print(Display.error("--timeout must be at least 1", use_color))
        return 2

    install_signal_handler()

    wordlist = load_wordlist(args.list_file, use_color)
    learning = LearningStore(args.cache_db, enabled=not args.no_cache)
    if not args.no_cache and not learning.available:
        print(Display.warn("learning store unavailable; continuing without cross-scan learning", use_color))

    checkpoint = None
    if args.checkpoint:
        checkpoint = Checkpoint(args.checkpoint)
        if path.isfile(args.checkpoint) and not args.no_resume:
            checkpoint.load()

    scanner = Scanner(args, learning, checkpoint)
    total_found = 0
    start = time.time()

    try:
        for url in args.urls:
            if STOP_EVENT.is_set():
                break
            try:
                total_found += scanner.scan(url, list(wordlist))
            except ValueError as exc:
                print(Display.error(sanitize_for_log(str(exc)), use_color))
            except requests.exceptions.RequestException:
                print(Display.error("target unreachable or connection failed", use_color))
    finally:
        elapsed = time.time() - start
        print("\n" + Display.section("summary", use_color))
        print(Display.info(f"elapsed: {elapsed:.2f}s | discoveries: {total_found}", use_color))

        bandit_stats = {a: s for a, s in scanner.bandit.stats().items() if s[0] > 0}
        if bandit_stats:
            print(Display.section("strategy performance (UCB1)", use_color))
            for arm, (pulls, mean) in sorted(bandit_stats.items(), key=lambda kv: kv[1][1], reverse=True):
                print(f"   {arm}: {pulls} tries, {mean * 100:.1f}% reward")

        if scanner.results:
            print(Display.section("discovered paths", use_color))
            for i, r in enumerate(sorted(scanner.results, key=lambda x: x['url']), 1):
                print(f"   {i}. {Display.status_bullet(r['status'], use_color)} {r['url']}")

        if args.output and scanner.results:
            if scanner.export(args.output, args.fmt):
                print(Display.good(f"results written to {args.output}", use_color))
            else:
                print(Display.error("failed to write output file", use_color))

        scanner.close()
        learning.close()

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
