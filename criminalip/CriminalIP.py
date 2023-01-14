import requests

import logging
from typing import Dict, List, Any, Optional, Tuple


logger = logging.getLogger('criminalip')


class CIPException(Exception):
    pass


class CIPLimitExcceed(Exception):
    pass


class Client(object):
    """CriminalIP Base client class"""
    api_url = "https://api.criminalip.io/v1/"

    def __init__(self, api_key: str):
        """CriminalIP Client Object
        Args:
            api_key (str): API Key
        """
        self._session = requests.Session()
        self._session.headers.update({"x-api-key": api_key})

    def request(
        self,
        method: str,
        uri: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        url = self.api_url + "/" + uri
        response = self._session.request(method, url, params=params, data=data)
        logger.debug(f"Response: {response.status_code}")
        if not response.ok:
            raise CIPException(
                f"Failed to request, error: {response.text}, method: {method}, url: {url}"
            )
        data = response.json()
        if data['status'] == 403:
            raise CIPLimitExcceed(data['message'])
        elif data['status'] != 200:
            raise CIPException(
                f"Failed to request, API status: {data['status']}, {data}, url: {url}"
            )
        return response.json()

    def get_user(self) -> Dict[str, Any]:
        """Get user data

        Returns:
            user_data (Dict[str, Any]): User data
        """
        result = self.request('POST', 'user/me')
        user_data = result["data"]
        return user_data


class IP(Client):
    def data(self, ip: str, is_full: bool = False) -> Dict[str, Any]:
        """Get Ip information

        Args:
            ip (str): IP address
            is_full (bool): return full data if it's True. [default: False]
        Returns:
            ip_data (Dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
            "full": is_full,
        }
        result = self.request("GET", "ip/data", params=params)
        return result

    def summary(self, ip: str):
        """Get Ip information

        Args:
            ip (str): IP address
            is_full (bool): return full data if it's True. [default: False]
        Returns:
            ip_data (Dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        result = self.request("GET", "ip/summary", params=params)
        return result

    def vpn(self, ip: str):
        """Get Ip information

        Args:
            ip (str): IP address
        Returns:
            ip_data (Dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        result = self.request("GET", "ip/vpn", params=params)
        return result

    def hosting(self, ip: str, is_full: bool = False):
        """API for Hosting IP Detection Information Inquery

        Args:
            ip (str): IP address
            is_full (bool): return full data if it's True. [default: False]
        Returns:
            ip_data (Dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
            "full": is_full,
        }
        result = self.request("GET", "ip/hosting", params=params)
        return result

    def malicious_info(self, ip: str):
        """Get Ip information

        Args:
            ip (str): IP address
        Returns:
            ip_data (Dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        result = self.request("GET", "feature/ip/malicious-info", params=params)
        return result

    def privacy_threat(self, ip: str):
        """Get Ip information

        Args:
            ip (str): IP address
        Returns:
            ip_data (Dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        result = self.request("GET", "feature/ip/privacy-threat", params=params)
        return result

    def is_safe_dns_server(self, ip: str):
        """Get Ip information

        Args:
            ip (str): IP address
        Returns:
            ip_data (Dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        result = self.request("GET", "feature/ip/is_safe_dns_server", params=params)
        return result


class Banner(Client):
    def search(self, query: str, offset: int = 0) -> Dict[str, Any]:
        """API for searching banner_data with filter

        Args:
            query (str): Domain saerch query
            offset (int): starting position in the dataset [default: 0]
        Returns:
            banners (List[Dict]): list of Banners
        TODO: pagination offset ?
        """
        params = {
            "query": query,
            "offset": offset,
        }
        result = self.request("GET", "banner/search", params=params)
        return result["data"]

    def stats(self, query: str) -> Dict[str, Any]:
        """API for providing statistics from banner_data search
        Args:
            query (str): Original searching text containing filters
        Returns:
            stats (Dict[str, Any]): Stats
        """
        result = self.request("GET", "banner/stats", params={"query": query})
        return result["data"]


class Domain(Client):
    def scan(self, query: str) -> str:
        """Request domain to scan

        Args:
            query (str): Domain search query
        Returns:
            scan_id (str): Scan Id
        """
        data = {
            "query": query,
        }
        result = self.request("POST", "domain/scan", data=data)
        scan_id = result['data']['scan_id']
        return scan_id

    def reports(self, query: str, offset: int = 0) -> Dict[str, Any]:
        """Get existing domain reports
        Args:
            query (str): Domain search query
            offset (int): starting position in the dataset [default: 0]
        Returns:
            reports (List[Dict]): list of Reports
        TODO: pagination offset ?
        """
        params = {
            "query": query,
            "offset": offset,
        }
        result = self.request("GET", "domain/reports", params=params)
        reports = result["data"]["reports"]
        return reports

    def report(self, scan_id: int) -> Dict[str, Any]:
        """Get Domain scan result

        Args:
            scan_id (str): Scan Id for request
        Returns:
            domain_scan_result (Dict[str, Any])
        """
        result = self.request("GET", f"domain/report/{scan_id}")
        domain_scan_result = result["data"]
        return domain_scan_result

    def status(self, scan_id: str) -> int:
        """Get progress of domain scan

        Args:
            query (str): Domain search query
        Returns:
            scan_percentage (int): Scan percentage
        """
        scan_status = self.request("GET", f"domain/status/{scan_id}")
        scan_percentage = scan_status["data"]["scan_percentage"]
        return scan_percentage


class Exploit(Client):
    def search(self, query: str, offset: int = 0) -> List[Dict]:
        """API for searching exploit data with filter

        Args:
            query (str): Original searching text containing filters
            offset (int): Starting position in the dataset(entering in increments of 10)
        Returns:
            exploits (List[Dict]): list of found Exploits
        TODO: pagination offset ?
        """
        params = {
            "query": query,
            "offset": offset,
        }
        result = self.request("GET", "exploit/search", params=params)
        exploits = result["data"]
        return exploits