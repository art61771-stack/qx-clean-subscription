#!/usr/bin/env python3
"""Opt-in public SS/Trojan collector. Python 3.10+, curl and sing-box 1.12."""
import argparse
import base64
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.parse as U
import urllib.request as R

METHODS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'}


def b64(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4)).decode()


def fetch(url):
    if not url.startswith('https://'):
        raise ValueError('Sources must use HTTPS')
    req = R.Request(url, headers={'User-Agent': 'QX-Public-Collector/1.0'})
    with R.urlopen(req, timeout=20) as r:
        if not r.url.startswith('https://'):
            raise ValueError('Insecure redirect')
        raw = r.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError('Source too large')
    return raw.decode('utf-8-sig')


def parse(line):
    """Intentionally reject transports/parameters QX export cannot preserve."""
    line = line.strip()
    if line.startswith('ss://'):
        body = line[5:].split('#', 1)[0]
        if '?' in body:
            body, query = body.split('?', 1)
            if query:
                raise ValueError('SS plugin/options not supported')
        if '@' not in body:
            body = b64(body)
        auth, address = body.rsplit('@', 1)
        auth = U.unquote(auth)
        if ':' not in auth:
            auth = b64(auth)
        method, password = auth.split(':', 1)
        if method not in METHODS:
            raise ValueError('Cipher not supported')
        u = U.urlsplit('ss://' + address)
        node = dict(type='shadowsocks', server=u.hostname, server_port=u.port,
                    method=method, password=password)
    elif line.startswith('trojan://'):
        u = U.urlsplit(line)
        q = U.parse_qs(u.query, keep_blank_values=True)
        if set(q) - {'sni', 'peer', 'security', 'type'}:
            raise ValueError('Unsupported Trojan parameters')
        if q.get('type', ['tcp']) != ['tcp'] or q.get('security', ['tls']) != ['tls']:
            raise ValueError('Unsupported Trojan transport')
        node = dict(type='trojan', server=u.hostname, server_port=u.port,
                    password=U.unquote(u.username or ''),
                    tls={'enabled': True, 'server_name': q.get('sni', q.get('peer', [u.hostname]))[0]})
    elif line.startswith('vmess://'):
        import uuid
        v = json.loads(b64(line[8:].split('#', 1)[0]))
        if v.get('net', 'tcp') not in ('tcp', 'ws') or v.get('type', 'none') not in ('none', ''):
            raise ValueError('Unsupported VMess transport')
        if v.get('tls', '') not in ('', 'none', 'tls') or v.get('alpn') or v.get('fp'):
            raise ValueError('Unsupported VMess TLS options')
        security = v.get('scy', 'auto') or 'auto'
        if security not in ('auto', 'aes-128-gcm', 'chacha20-poly1305', 'none'):
            raise ValueError('Unsupported VMess security')
        node = dict(type='vmess', server=v['add'], server_port=int(v['port']),
                    uuid=str(uuid.UUID(v['id'])), security=security, alter_id=int(v.get('aid', 0)))
        if node['alter_id'] != 0:
            raise ValueError('Legacy VMess not supported')
        if v.get('net') == 'ws':
            node['transport'] = {'type': 'ws', 'path': v.get('path') or '/'}
            if v.get('host'):
                node['transport']['headers'] = {'Host': v['host']}
        if v.get('tls') == 'tls':
            node['tls'] = {'enabled': True, 'server_name': v.get('sni') or v.get('host') or v['add']}
    else:
        raise ValueError('Unsupported protocol')
    credential = node.get('password', node.get('uuid'))
    if not node['server'] or not node['server_port'] or not credential:
        raise ValueError('Incomplete node')
    # Reject ambiguous QX syntax rather than emit a malformed subscription.
    for value in [node['server'], credential, node.get('tls', {}).get('server_name', ''),
                  node.get('transport', {}).get('path', ''),
                  node.get('transport', {}).get('headers', {}).get('Host', '')]:
        if any(c in value for c in ',\r\n'):
            raise ValueError('QX-unsafe field')
    return node


def public_server(host):
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return bool(addresses) and all(ipaddress.ip_address(a[4][0]).is_global for a in addresses)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def curl(port, url, timing=False):
    cmd = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '',
           '--proxy', f'socks5h://127.0.0.1:{port}', '--connect-timeout', '4',
           '--max-time', '8', '--proto', '=https', '--max-filesize', '65536']
    if timing:
        cmd += ['--output', os.devnull, '--write-out', '%{http_code} %{time_total}']
    r = subprocess.run(cmd + [url], capture_output=True, timeout=10, check=True)
    return r.stdout.decode()


class RiskCache:
    def __init__(self):
        import threading
        self.lock = threading.Lock()
        self.items = {}

    def check(self, ip, max_risk):
        # Serialize/cache queries to stay within public API limits.
        with self.lock:
            if ip not in self.items:
                value = json.loads(fetch('https://proxycheck.io/v2/' + ip + '?vpn=1&risk=1'))
                data = value.get(ip, {})
                risk = data.get('risk')
                if value.get('status') != 'ok' or data.get('proxy') not in ('yes', 'no') or risk is None:
                    raise ValueError('Risk result unavailable')
                self.items[ip] = (data['proxy'], float(risk))
            proxy, score = self.items[ip]
        return proxy == 'no' and score <= max_risk, score


RISK = RiskCache()
import collections
import threading
STATS = collections.Counter()
STATS_LOCK = threading.Lock()


def mark(reason):
    with STATS_LOCK:
        STATS[reason] += 1


def test_node(node, args):
    try:
        if not public_server(node['server']):
            return None
        port = free_port()
        config = {'log': {'disabled': True},
                  'inbounds': [{'type': 'socks', 'tag': 'in', 'listen': '127.0.0.1', 'listen_port': port}],
                  'outbounds': [dict(node, tag='proxy')], 'route': {'final': 'proxy'}}
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'config.json'
            cfg.write_text(json.dumps(config))
            cfg.chmod(0o600)
            p = subprocess.Popen([args.sing_box, 'run', '-c', str(cfg)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(40):
                    if p.poll() is not None:
                        return None
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    return None
                samples = []
                for _ in range(3):
                    code, seconds = curl(port, 'https://www.gstatic.com/generate_204', True).split()
                    ms = float(seconds) * 1000
                    if code != '204' or ms > args.max_latency:
                        mark('https_latency_or_status_rejected')
                        return None
                    samples.append(ms)
                ip = curl(port, 'https://api.ipify.org').strip()
                if not ipaddress.ip_address(ip).is_global:
                    return None
                clean, risk = RISK.check(ip, args.max_risk)
                if not clean:
                    mark('risk_rejected')
                    return None
                mark('passed')
                return {'node': node, 'latency_ms': round(statistics.median(samples), 1),
                        'max_latency_ms': round(max(samples), 1), 'risk': risk, 'ip': ip}
            finally:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
    except Exception:
        # Do not leak credentials/source URLs into public Actions logs.
        mark('connection_or_query_failed')
        return None


def qx(result, index):
    n = result['node']
    server = n['server']
    if ':' in server:
        server = '[' + server + ']'
    head = n['type']
    credential = n.get('password', n.get('uuid'))
    line = f"{head}={server}:{n['server_port']}, password={credential}"
    if head == 'shadowsocks':
        line += ', method=' + n['method']
    elif head == 'vmess':
        method = {'auto': 'aes-128-gcm', 'chacha20-poly1305': 'chacha20-poly1305'}.get(n['security'], n['security'])
        line += ', method=' + method
        ws = n.get('transport')
        if ws:
            line += ', obfs=' + ('wss' if n.get('tls') else 'ws') + ', obfs-uri=' + ws['path']
            if ws.get('headers', {}).get('Host'):
                line += ', obfs-host=' + ws['headers']['Host']
        elif n.get('tls'):
            line += ', obfs=over-tls, obfs-host=' + n['tls']['server_name']
    if n.get('tls'):
        if head == 'trojan':
            line += ', over-tls=true'
        line += ', tls-verification=true, tls-host=' + n['tls']['server_name']
    return line + f", udp-relay=false, tag=Clean-{index:02d}-{result['latency_ms']:.0f}ms"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--count', type=int, default=20)
    ap.add_argument('--max-latency', type=float, default=200)
    ap.add_argument('--max-risk', type=float, default=10)
    ap.add_argument('--max-candidates', type=int, default=150)
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--sources', default='sources.json')
    ap.add_argument('--output', default='public')
    ap.add_argument('--sing-box', default='sing-box')
    args = ap.parse_args()
    if not (1 <= args.count <= 100 and 1 <= args.max_candidates <= 300 and
            1 <= args.workers <= 8 and 0 < args.max_latency <= 5000 and 0 <= args.max_risk <= 100):
        ap.error('Arguments outside safe limits')
    sources = json.loads(Path(args.sources).read_text())
    # Optional source URLs remain in Actions secrets, never in logs/report.
    for url in os.environ.get('SOURCE_URLS', '').splitlines():
        if url.strip():
            sources.append({'url': url.strip(), 'redistribution_allowed': True})
    candidates, seen = [], set()
    source_errors = 0
    for source in sources:
        if source.get('redistribution_allowed') is not True:
            continue
        try:
            text = fetch(source['url'])
            if source.get('format') == 'selfbuilt-markdown':
                text = text.split('## 自建节点', 1)[1].split('====================================================', 1)[0]
            elif source.get('format') == 'telegram-selfbuilt':
                import re
                import html
                chunks = re.split(r'data-post="', text)[1:]
                selected_posts = []
                for chunk in chunks:
                    match = re.search(r'<div class="tgme_widget_message_text[^>]*>(.*?)</div>', chunk, re.S)
                    if match:
                        body = html.unescape(re.sub(r'<[^>]+>', '\n', match.group(1)))
                        if '自建' in body and '转发请标注来源' in body and '匿名' not in body:
                            selected_posts.append(body)
                text = '\n'.join(selected_posts)
            if not any(p in text for p in ('ss://', 'trojan://', 'vmess://', 'vless://')):
                text = b64(''.join(text.split()))
            import re
            lines = re.findall(r'(?:ss|trojan|vmess)://[^\s<>`]+', text)
            for line in lines:
                try:
                    node = parse(line)
                    key = json.dumps(node, sort_keys=True)
                    if key not in seen and len(candidates) < args.max_candidates:
                        seen.add(key)
                        candidates.append(node)
                except Exception:
                    continue
        except Exception:
            source_errors += 1
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for result in pool.map(lambda n: test_node(n, args), candidates):
            if result:
                results.append(result)
    # Avoid filling the list with duplicate exits.
    selected, exits = [], set()
    for r in sorted(results, key=lambda r: r['latency_ms']):
        if r['ip'] not in exits and len(selected) < args.count:
            exits.add(r['ip'])
            selected.append(r)
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    header = f'# Updated {now}; passed {len(selected)}/{args.count}; GitHub runner measurements\n'
    for source in sources:
        if source.get('attribution'):
            header += '# Source: ' + source['attribution'].replace('\n', ' ') + '\n'
    (out / 'qx.txt').write_text(header + '\n'.join(qx(r, i) for i, r in enumerate(selected, 1)) + '\n')
    report = {'updated_at': now, 'requested': args.count, 'selected': len(selected),
              'candidates': len(candidates), 'source_errors': source_errors,
              'candidate_protocols': dict(collections.Counter(n['type'] for n in candidates)),
              'test_outcomes': dict(STATS),
              'latency_limit_ms': args.max_latency, 'risk_limit': args.max_risk,
              'measurement': '3 HTTPS total-time samples, all <= limit; median ranking',
              'screening': 'proxycheck.io proxy=no and risk<=limit; unknown rejected',
              'results': [{k: v for k, v in r.items() if k not in ('node', 'ip')} for r in selected]}
    (out / 'status.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"Candidates: {len(candidates)}; selected: {len(selected)}/{args.count}; source errors: {source_errors}")
    # Empty output deliberately replaces stale credentials, rather than falsely
    # presenting an old list as recently verified.


if __name__ == '__main__':
    main()
