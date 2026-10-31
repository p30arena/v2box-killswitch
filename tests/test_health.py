from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from health import HealthProbe
from policy import PolicyError, compile_policy


class HealthTests(unittest.TestCase):
    def probe(self, run=None, verify=None, address="1.1.1.1", url="https://health.example.invalid/check"):
        return HealthProbe(url, address, 204,
                           run or (lambda *a, **k: SimpleNamespace(returncode=0, stdout="204 " + address)),
                           verify or (lambda _: True))

    def test_success_is_target_reachability_only(self):
        self.assertEqual(self.probe().check("utun3").health, "usable")

    def test_pinned_interface_no_dns_proxy_redirect_or_curlrc(self):
        calls = []
        def run(args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout="204 1.1.1.1")
        self.probe(run).check("utun3")
        args, kwargs = calls[0]
        self.assertEqual(args[:2], ["/usr/bin/curl", "--disable"])
        self.assertIn("if!utun3", args)
        self.assertIn("health.example.invalid:443:1.1.1.1", args)
        self.assertNotIn("--location", args)
        self.assertNotIn("--insecure", args)
        self.assertEqual(kwargs["timeout"], 7)
        self.assertNotIn("HTTPS_PROXY", kwargs["env"])

    def test_invalid_or_unowned_tunnel_sends_nothing(self):
        def forbidden(*a, **k): raise AssertionError("probe must not run")
        self.assertEqual(self.probe(forbidden).check("en0").health, "unverified")
        self.assertEqual(self.probe(forbidden, verify=lambda _: False).check("utun3").health, "unverified")

    def test_identity_rechecked_after_probe(self):
        replies = iter([True, False])
        self.assertEqual(self.probe(verify=lambda _: next(replies)).check("utun3").reason, "tunnel_changed")

    def test_redirect_wrong_address_and_http_failure_are_not_healthy(self):
        for output in ("302 1.1.1.1", "204 8.8.8.8", "500 1.1.1.1"):
            with self.subTest(output=output):
                run = lambda *a, **k: SimpleNamespace(returncode=0, stdout=output)
                self.assertEqual(self.probe(run).check("utun3").health, "unusable")

    def test_bad_output_is_unverified(self):
        run = lambda *a, **k: SimpleNamespace(returncode=0, stdout="garbage")
        self.assertEqual(self.probe(run).check("utun3").health, "unverified")

    def test_tls_error_or_timeout_is_unusable(self):
        run = lambda *a, **k: SimpleNamespace(returncode=60, stdout="")
        self.assertEqual(self.probe(run).check("utun3").health, "unusable")
        def timeout(*a, **k): raise subprocess.TimeoutExpired("curl", 7)
        self.assertEqual(self.probe(timeout).check("utun3").reason, "probe_timeout")

    def test_unsupported_curl_does_not_trigger_restart(self):
        run = lambda *a, **k: SimpleNamespace(returncode=2, stdout="")
        self.assertEqual(self.probe(run).check("utun3").health, "unverified")

    def test_ipv6_pin_bracketed(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0, stdout="204 2606:4700:4700::1111")
        self.probe(run, address="2606:4700:4700::1111").check("utun3")
        self.assertIn("health.example.invalid:443:[2606:4700:4700::1111]", calls[0])

    def test_unsafe_urls_and_targets_rejected(self):
        for url in ("http://health.example.invalid/check", "https://user:secret@health.example.invalid/",
                    "https://health.example.invalid/?token=secret", "https://health.example.invalid/#fragment"):
            with self.subTest(url=url), self.assertRaises(ValueError): self.probe(url=url)
        for address in ("192.168.1.1", "ff02::1", "224.0.0.1", "vpn.example.invalid"):
            with self.subTest(address=address), self.assertRaises(ValueError): self.probe(address=address)

    def test_multicast_endpoint_rejected(self):
        for address in ("224.0.0.1", "ff0e::1"):
            with self.subTest(address=address), self.assertRaises(PolicyError):
                compile_policy({"physical": ["en0"], "endpoints": [{"address": address, "port": 443, "protocol": "tcp"}]})


if __name__ == "__main__": unittest.main()
