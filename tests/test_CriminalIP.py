import os
import time
import unittest

from criminalip import CriminalIP
from criminalip import User
from criminalip.exceptions import CIPLimitExcceed


""" CONSTANTS """


is_overall_limit_excceeded = False


""" TEST Cases """


def test_client():
    client = CriminalIP(os.getenv("BASE_URL"), os.getenv("API_KEY"))
    assert isinstance(client.get_user(), User)


class TestCriminalIP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = CriminalIP(os.getenv("BASE_URL"), os.getenv("API_KEY"))

    def test_ip_report(self):
        result = self.client.ip_report("1.1.1.1", full=False)
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_ip_summary(self):
        result = self.client.ip_summary("1.1.1.1")
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_ip_vpn(self):
        result = self.client.ip_vpn("1.1.1.1")
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_ip_hosting(self):
        result = self.client.ip_hosting("1.1.1.1", is_full=False)
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_ip_malicious_info(self):
        result = self.client.ip_malicious_info("1.1.1.1")
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_ip_privacy_threat(self):
        result = self.client.ip_privacy_threat("1.1.1.1")
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_is_safe_dns_server(self):
        result = self.client.is_safe_dns_server("1.1.1.1")
        self.assertTrue("is_safe_dns_server" in result, msg=f"{result}")

    def test_ip_suspicious_info(self):
        result = self.client.ip_suspicious_info("1.1.1.1")
        self.assertTrue("is_safe_dns_server" in result, msg=f"{result}")

    def test_banner_search(self):
        query = "ssh"
        banners = self.client.banner_search(query, offset=0)
        self.assertTrue("as_name" in banners["result"][0])

    def test_banner_stats(self):
        query = "ssh"
        banners = self.client.banner_stats(query)
        self.assertTrue("as_name_agg" in banners["result"])

    def test_search_exploit(self):
        result = self.client.search_exploit("cve_id:cve-2006-5911")
        self.assertEqual(result["result"][0]["cve_id"][0], "CVE-2006-5911")

    def test_domain_reports(self):
        try:
            reports = self.client.domain_reports("google.com")
        except CIPLimitExcceed:
            self.skipTest("Domain API limit has been exceeded")
        self.assertTrue("countries" in reports[0])

    def test_domain_scan(self):
        is_limit_exceeded = False
        with self.subTest(command="scan"):
            try:
                scan_id = self.client.domain_scan("aispera.com")
            except CIPLimitExcceed:
                is_limit_exceeded = True
                self.skipTest("Domain API limit has been exceeded.")
            self.assertTrue(scan_id and isinstance(scan_id, int))

        with self.subTest(command="status"):
            if is_limit_exceeded:
                self.skipTest("Domain API limit has been exceeded.")
            retry = 0
            while retry < 10:
                status = self.client.domain_scan_status(scan_id)
                if status == 100:
                    break
                time.sleep(2)
                retry += 1
            self.assertTrue(
                retry < 10 and status == 100, msg=f"Retry: {retry}, status: {status}"
            )

        with self.subTest(command="report"):
            if is_limit_exceeded:
                self.skipTest("Domain API limit has been exceeded.")
            report = self.client.domain_report(scan_id)
            self.assertTrue("certificates" in report)
