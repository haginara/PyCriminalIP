import os
import time
import unittest

from criminalip.CriminalIP import Client
from criminalip import IP
from criminalip import Banner
from criminalip import Domain
from criminalip import Exploit

from criminalip.CriminalIP import CIPLimitExcceed


""" CONSTANTS """


is_overall_limit_excceeded = False


""" TEST Cases """


def test_client():
    client = Client(os.getenv("API_KEY"))
    assert "name" in client.get_user()


class TestIP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = IP(os.getenv("API_KEY"))

    def test_data(self):
        result = self.client.data("1.1.1.1", is_full=False)
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_summary(self):
        result = self.client.summary("1.1.1.1")
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_vpn(self):
        result = self.client.vpn("1.1.1.1")
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_hosting(self):
        result = self.client.hosting("1.1.1.1", is_full=False)
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_malicious_info(self):
        result = self.client.malicious_info("1.1.1.1")
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_privacy_threat(self):
        result = self.client.privacy_threat("1.1.1.1")
        self.assertEqual(result.get("ip"), "1.1.1.1", msg=f"{result}")

    def test_is_safe_dns_server(self):
        result = self.client.is_safe_dns_server("1.1.1.1")
        self.assertTrue("is_safe_dns_server" in result, msg=f"{result}")


class TestBanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = Banner(os.getenv("API_KEY"))

    def test_search(self):
        query = "ssh"
        banners = self.client.search(query, offset=0)
        self.assertTrue("as_name" in banners["result"][0])

    def test_stats(self):
        query = "ssh"
        banners = self.client.stats(query)
        self.assertTrue("as_name_agg" in banners["result"])


class TestExploit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = Exploit(os.getenv("API_KEY"))

    def test_search(self):
        result = self.client.search("cve_id:cve-2006-5911")
        self.assertEqual(result["result"][0]["cve_id"][0], "CVE-2006-5911")


class TestDomain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = Domain(os.getenv("API_KEY"))

    def test_reports(self):
        try:
            reports = self.client.reports("google.com")
        except CIPLimitExcceed:
            self.skipTest("Domain API limit has been exceeded")
        self.assertTrue("countries" in reports[0])

    def test_scan(self):
        is_limit_exceeded = False
        with self.subTest(command="scan"):
            try:
                scan_id = self.client.scan("aispera.com")
            except CIPLimitExcceed:
                is_limit_exceeded = True
                self.skipTest("Domain API limit has been exceeded.")
            self.assertTrue(scan_id and isinstance(scan_id, int))

        with self.subTest(command="status"):
            if is_limit_exceeded:
                self.skipTest("Domain API limit has been exceeded.")
            retry = 0
            while retry < 10:
                status = self.client.status(scan_id)
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
            report = self.client.report(scan_id)
            self.assertTrue("certificates" in report)
