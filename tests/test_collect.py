import base64
import unittest
from unittest.mock import patch
import collect as c


class Tests(unittest.TestCase):
    def test_ss(self):
        auth = base64.urlsafe_b64encode(b'aes-128-gcm:secret').decode().rstrip('=')
        n = c.parse(f'ss://{auth}@example.com:443#name')
        self.assertEqual(n['password'], 'secret')
        text = c.qx({'node': n, 'latency_ms': 20}, 1)
        self.assertIn('method=aes-128-gcm', text)
        self.assertIn('tag=Clean-01-20ms', text)

    def test_trojan(self):
        n = c.parse('trojan://secret@example.com:443?sni=tls.example.com')
        self.assertTrue(n['tls']['enabled'])
        self.assertIn('tls-verification=true', c.qx({'node': n, 'latency_ms': 10}, 1))

    def test_vmess_ws(self):
        import json
        data = dict(add='example.com', port='443', id='969f1909-c0d3-4c30-813d-3aec5c838b7d',
                    aid='0', net='ws', type='none', tls='tls', host='tls.example.com', path='/ws')
        uri = 'vmess://' + base64.b64encode(json.dumps(data).encode()).decode()
        n = c.parse(uri)
        self.assertEqual(n['transport']['path'], '/ws')
        text = c.qx({'node': n, 'latency_ms': 15}, 1)
        self.assertIn('obfs=wss', text)
        self.assertIn('method=aes-128-gcm', text)

    def test_reject_options(self):
        for line in ['ss://YWVzLTEyOC1nY206eA@example.com:443?plugin=abc',
                     'trojan://x@example.com:443?allowInsecure=1',
                     'trojan://x@example.com:443?type=ws',
                     'trojan://x%2Cy@example.com:443',
                     'vmess://abc']:
            with self.assertRaises(ValueError):
                c.parse(line)

    def test_risk_fail_closed(self):
        with patch.object(c, 'fetch', return_value='{"status":"denied"}'):
            with self.assertRaises(ValueError):
                c.RiskCache().check('1.1.1.1', 10)

    def test_risk_reject_proxy(self):
        response = '{"status":"ok","1.1.1.1":{"proxy":"yes","risk":0}}'
        with patch.object(c, 'fetch', return_value=response):
            self.assertFalse(c.RiskCache().check('1.1.1.1', 10)[0])

    def test_private_destination(self):
        self.assertFalse(c.public_server('127.0.0.1'))
        self.assertFalse(c.public_server('::1'))


if __name__ == '__main__':
    unittest.main()
