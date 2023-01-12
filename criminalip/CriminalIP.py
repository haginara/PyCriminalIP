import requests

from typing import Dict, List, Any, Optional, Tuple


class CIPException(Exception):
    pass


class Client(object):
    base_url = "https://api.criminalip.io/v1"

    def __init__(self, api_key: str):
        """CriminalIP Client Object
        Args:
            api_key (str): API Key
        """
        self._session = requests.Session()
        self._session.headers.update({"x-api-key": api_key})

    @property
    def api_url(self):
        return self.get_api_url()

    def get_api_url(self):
        raise NotImplemented

    def request(
        self,
        method: str,
        uri: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        url = self.api_url + "/" + uri
        response = self._session.request(
            method, url, headers=self.headers, params=params, data=data
        )
        if not response.ok:
            raise CIPException(
                f"Failed to request, error: {response.text}, method: {method}, uri: {uri}"
            )
        return response.json()

    def get_user(self) -> Dict[str, Any]:
        """Get user data

        Returns:
            data (Dict[str, Any]): User data
        """
        response = self._session.request("POST", self.base_url + "/user/me")
        if not response.ok:
            raise CIPException(
                f"Failed to get user data, error: {response.text}, uri: /user/me"
            )
        data = response.json()["data"]
        return data


class IP(Client):
    def get_api_url(self):
        return self.base_url + "/ip/"

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
        result = self.request("GET", "data", params=params)
        return result

    def summary(self):
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
        result = self.request("GET", "summary", params=params)
        return result

    def vpn(self):
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
        result = self.request("GET", "vpn", params=params)
        return result

    def hosting(self):
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
        result = self.request("GET", "hosting", params=params)
        return result

    def malicious_info(self):
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
        result = self.request("GET", "malicious-info", params=params)
        return result

    def privacy_threat(self):
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
        result = self.request("GET", "privacy-threat", params=params)
        return result

    def is_safe_dns_server(self):
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
        result = self.request("GET", "is_safe_dns_server", params=params)
        return result


class Banner(Client):
    def get_api_url(self):
        return self.base_url + "/banner/"

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
        result = self.request("GET", "search", params=params)
        return result['data']

    def stats(self, query: str) -> Dict[str, Any]:
        """API for providing statistics from banner_data search
        Args:
            query (str): Original searching text containing filters
        Returns:
            stats (Dict[str, Any]): Stats
        """
        result = self.request("GET", 'stats', params={'query': query})
        return result['data']


class Domain(Client):
    def get_api_url(self):
        return self.base_url + "/domain/"

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
        result = self.request("GET", "scan", data=data)
        return result

    def reports(self, query: str, offset: int = 0) -> Dict[str, Any]:
        """Get existing domain reports
        Args:
            query (str): Domain saerch query
            offset (int): starting position in the dataset [default: 0]
        Returns:
            reports (List[Dict]): list of Reports
        TODO: pagination offset ?
        """
        params = {
            "query": query,
            "offset": offset,
        }
        result = self.request("GET", "reports", params=params)
        reports = result['data']['reports']
        return reports

    def report(self, scan_id: str) -> Dict[str, Any]:
        """Get Domain scan result

        Args:
            scan_id (str): Scan Id for request
        Returns:
            domain_scan_result (Dict[str, Any])
        """
        result = self.request("GET", f"report/{scan_id}")
        domain_scan_result = result['data']
        return domain_scan_result

    def status(self, scan_id: str) -> int:
        """Get progress of domain scan

        Args:
            query (str): Domain search query
        Returns:
            scan_percentage (int): Scan percentage
        """
        scan_status = self.request("GET", f"status/{scan_id}")
        scan_percentage = scan_status['data']['scan_percentage']
        return scan_percentage
