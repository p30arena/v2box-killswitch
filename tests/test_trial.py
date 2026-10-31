import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from trial import evaluate_ipv4_trial


class TrialTests(unittest.TestCase):
    def setUp(self):
        self.report = {"capture_started": True, "capture_kernel_drops": {"en0": 0},
                       "outbound_dns_headers": 0, "direct_tcp_probe_headers": 0,
                       "outbound_transport_headers": 5, "ipv4_tested_interfaces": ["en0"],
                       "probes": [{"interface": "en0", "protocol": p, "outcome": "connection_failed"}
                                  for p in ("tcp", "dns", "router_dns")],
                       "block_counter_before": 10, "block_counter_after": 13,
                       "health": "usable", "router_ping": "success", "router_ping_by_interface": {"en0": "success"},
                       "ipv6": "not_tested"}

    def test_complete_limited_evidence(self):
        self.assertEqual(evaluate_ipv4_trial(self.report), (True, "limited_ipv4_checks_passed"))
        self.assertEqual(self.report["ipv6"], "not_tested")

    def test_missing_any_evidence_rejects(self):
        for key in self.report:
            if key == "ipv6": continue
            report = copy.deepcopy(self.report)
            del report[key]
            with self.subTest(key=key): self.assertFalse(evaluate_ipv4_trial(report)[0])

    def test_counter_reset_is_inconclusive(self):
        self.report.update(block_counter_before=3, block_counter_after=2)
        self.assertEqual(evaluate_ipv4_trial(self.report)[1], "block_counter_insufficient_or_reset")

    def test_lossy_capture_rejects(self):
        for value in (1, None, True):
            self.report["capture_kernel_drops"] = {"en0": value}
            self.assertFalse(evaluate_ipv4_trial(self.report)[0])

    def test_any_direct_packet_rejects(self):
        for field in ("outbound_dns_headers", "direct_tcp_probe_headers"):
            report = copy.deepcopy(self.report)
            report[field] = 1
            self.assertFalse(evaluate_ipv4_trial(report)[0])

    def test_failed_binding_or_success_does_not_confirm(self):
        for outcome in ("inconclusive_binding_failed", "unexpected_success"):
            self.report["probes"][0]["outcome"] = outcome
            self.assertFalse(evaluate_ipv4_trial(self.report)[0])

    def test_missing_router_dns_probe_rejects(self):
        self.report["probes"].pop()
        self.assertFalse(evaluate_ipv4_trial(self.report)[0])

    def test_uncaptured_interface_rejects(self):
        self.report["ipv4_tested_interfaces"].append("en1")
        self.assertFalse(evaluate_ipv4_trial(self.report)[0])

    def test_no_transport_packet_rejects(self):
        self.report["outbound_transport_headers"] = 0
        self.assertFalse(evaluate_ipv4_trial(self.report)[0])

    def test_no_mutation(self):
        before = copy.deepcopy(self.report)
        evaluate_ipv4_trial(self.report)
        self.assertEqual(self.report, before)


if __name__ == "__main__": unittest.main()
