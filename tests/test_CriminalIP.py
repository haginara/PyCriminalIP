import os
import unittest

from criminalip.CriminalIP import Client
from criminalip.CriminalIP import IP
from criminalip.CriminalIP import Banner
from criminalip.CriminalIP import Domain
from criminalip.CriminalIP import Exploit


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
        self.assertTrue('as_name' in banners['result'][0])
    
    def test_stats(self):
        query = "ssh"
        banners = self.client.stats(query)
        self.assertTrue('as_name_agg' in banners['result'])


class TestExploit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = Exploit(os.getenv("API_KEY"))
    
    def test_search(self):
        result = self.client.search('cve_id:cve-2006-5911')
        self.assertEqual(result['result'][0]['cve_id'][0], 'CVE-2006-5911')


class TestDomain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = Domain(os.getenv("API_KEY"))
    
    def test_reports(self):
        reports = self.client.reports('google.com')
        self.assertTrue('countries' in reports[0])
