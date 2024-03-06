import os
import pprint
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
        info = self.client.ip_suspicious_info("1.1.1.1")
        info
        self.assertTrue("abuse_record_count" in info, msg=pprint.pformat(info))

    def test_banner_search(self):
        query = "ssh"
        results = self.client.banner_search(query, offset=0)
        banners: list[dict] = results["data"]["result"]
        self.assertTrue("as_name" in banners[0], msg=f"{banners=}")

    def test_banner_stats(self):
        query = "ssh"
        results = self.client.banner_stats(query)
        banners: list[dict] = results["data"]["result"]
        self.assertTrue("as_name_agg" in banners, msg=f"{banners=}")

    def test_search_exploit(self):
        cve_id = "cve-2022-22965"
        result = self.client.search_exploit(f"cve_id:{cve_id}")
        exploit = result["data"]["result"]
        # BUG: API Not working - 2024/03/01
        #self.assertEqual(exploit[0]["cve_id"][0], cve_id, msg=f"{result=}")

    def test_domain_reports(self):
        try:
            results = self.client.domain_reports("google.com")
            reports = results["data"]["reports"]
        except CIPLimitExcceed:
            self.skipTest("Domain API limit has been exceeded")
        self.assertTrue("connected_ip_cnt" in reports[0], msg=pprint.pformat(reports[0]))

    def test_domain_scan(self):
        is_limit_exceeded = False
        with self.subTest(command="scan"):
            try:
                scan_id = self.client.domain_scan("example.com")
            except CIPLimitExcceed:
                is_limit_exceeded = True
                self.skipTest("Domain API limit has been exceeded.")
            self.assertTrue(scan_id and isinstance(scan_id, int), msg=f"{scan_id=}")

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
            self.assertTrue("certificates" in report, msg=f"{report=}")
