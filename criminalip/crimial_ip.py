import logging
from dataclasses import dataclass

from .api import (
    ApiClient,
    RequestRoute,
    Response,
    response
)


@dataclass
class User:
    account_type: str
    api_key: str
    email: str
    last_access_date: str
    max_search: str
    membership_date: str
    name: str

    @classmethod
    def map_model(cls, data):
        return cls(**data["data"])


class CriminalIP(ApiClient):
    def __init__(self, base_url, api_key):
        super(CriminalIP, self).__init__(base_url)
        self.headers["x-api-key"] = api_key

    @Response(model=User)
    @RequestRoute("POST", "v1/user/me")
    def get_user(self):
        return (None, None, None)

    @RequestRoute("GET", "v1/asset/ip/report")
    def ip_report(self, ip: str, full: bool = False):
        params = {"ip": ip, "full": full}
        return (params, None, None)

    @RequestRoute("GET", "v1/ip/summary")
    def ip_summary(self, ip: str):
        """Get Ip information
        Args:
            ip (str): IP address
            is_full (bool): return full data if it's True. [default: False]
        Returns:
            ip_data (dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        return (params, None, None)

    @RequestRoute("GET", "v1/ip/vpn")
    def ip_vpn(self, ip: str):
        """Get Ip information

        Args:
            ip (str): IP address
        Returns:
            ip_data (dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        return params, None, None

    @RequestRoute("GET", "v1/ip/hosting")
    def ip_hosting(self, ip: str, is_full: bool = False):
        """API for Hosting IP Detection Information Inquery
        Args:
            ip (str): IP address
            is_full (bool): return full data if it's True. [default: False]
        Returns:
            ip_data (dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
            "full": is_full,
        }
        return params, None, None

    @RequestRoute("GET", "v1/feature/ip/malicious-info")
    def ip_malicious_info(self, ip: str):
        """Get Ip information
        Args:
            ip (str): IP address
        Returns:
            ip_data (dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        return params, None, None

    @RequestRoute("GET", "v1/feature/ip/privacy-threat")
    def ip_privacy_threat(self, ip: str):
        """Get Ip information
        Args:
            ip (str): IP address
        Returns:
            ip_data (dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        return params, None, None

    @RequestRoute("GET", "v1/feature/ip/is_safe_dns_server")
    def is_safe_dns_server(self, ip: str):
        """Get Ip information
        Args:
            ip (str): IP address
        Returns:
            ip_data (dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        return params, None, None

    @RequestRoute("GET", "v2/feature/ip/suspicious-info")
    def ip_suspicious_info(self, ip: str):
        params = {"ip": ip}
        return params, None, None

    @RequestRoute("GET", "v1/banner/search")
    def banner_search(self, query: str, offset: int = 0):
        """API for searching banner_data with filter
        Args:
            query (str): Domain saerch query
            offset (int): starting position in the dataset [default: 0]
        Returns:
            banners (List[dict]): list of Banners
        TODO: pagination offset ?
        """
        params = {
            "query": query,
            "offset": offset,
        }
        # return result["data"]
        return params, None, None

    @RequestRoute("GET", "v1/banner/stats")
    def banner_stats(self, query: str):
        """API for providing statistics from banner_data search
        Args:
            query (str): Original searching text containing filters
        Returns:
            stats (dict[str, Any]): Stats
        """
        params = {"query": query}
        # return result["data"]
        return params, None, None

    @response(func=lambda d: d["data"].get("scan_id"))
    @RequestRoute("POST", "v1/domain/scan/")
    def domain_scan(self, query: str):
        """Request domain to scan
        Args:
            query (str): Domain search query
        Returns:
            scan_id (str): Scan Id
        """
        data = {
            "query": query,
        }
        # scan_id = result["data"]["scan_id"]
        return self.return_params(data=data)

    @RequestRoute("POST", "v1/domain/scan/private")
    def domain_private_scan(self, query: str):
        """Request domain to scan privately
        Args:
            query (str): Domain search query
        Returns:
            scan_id (str): Scan Id
        """
        data = {
            "query": query,
        }
        # scan_id = result["data"]["scan_id"]
        return None, data, None

    @RequestRoute("GET", "v1/domain/reports")
    def domain_reports(self, query: str, offset: int = 0):
        """Get existing domain reports
        Args:
            query (str): Domain search query
            offset (int): starting position in the dataset [default: 0]
        Returns:
            reports (List[dict]): list of Reports
        TODO: pagination offset ?
        """
        params = {
            "query": query,
            "offset": offset,
        }
        # reports = result["data"]["reports"]
        return params, None, None

    @RequestRoute("GET", "v1/domain/report/<scan_id>")
    def domain_report(self, scan_id: int):
        """Get Domain scan result
        Args:
            scan_id (str): Scan Id for request
        Returns:
            domain_scan_result (dict[str, Any])
        """
        # domain_scan_result = result["data"]
        return None, None, None

    @RequestRoute("GET", "v1/domain/status/<scan_id>")
    def domain_scan_status(self, scan_id: str) -> int:
        """Get progress of domain scan

        Args:
            query (str): Domain search query
        Returns:
            scan_percentage (int): Scan percentage
        """
        # scan_percentage = scan_status["data"]["scan_percentage"]
        return None, None, None

    @RequestRoute("GET", "v1/domain/reports/personal")
    def scan_history(
        self,
        offset: int,
        show_public: bool = False,
        show_private: bool = False,
        scan_type: str = "lite",
    ):
        if scan_type not in ("full", "lite"):
            raise Exception("scan_type must be full or lite")
        params = dict(
            offset=offset,
            show_public=show_public,
            show_private=show_private,
            scan_type=scan_type,
        )
        return params, None, None

    @RequestRoute("GET", "v1/domain/lite/scan")
    def domain_lite_scan(self, query: str):
        params = {"query": query}
        # data['data']['scan_id]
        return params, None, None

    @RequestRoute("GET", "v1/domain/lite/progress")
    def domain_lite_progress(self, scan_id: str):
        params = {"scan_id": scan_id}
        return params, None, None

    @RequestRoute("GET", "v1/domain/lite/report/<scan_id>")
    def domain_lite_report(self, scan_id: str):
        return None, None, None

    @RequestRoute("GET", "v1/domain/quick/hash/view")
    def check_domain(self, domain: str):
        params = {"domain": domain}
        return params, None, None

    @RequestRoute("GET", "v1/domain/quick/malicious/view")
    def check_domain_malicious(self, domain: str):
        params = {"domain": domain}
        return params, None, None

    @RequestRoute("GET", "v1/domain/quick/trusted/view")
    def check_domain_trusted(self, domain: str):
        params = {"domain": domain}
        return params, None, None

    @RequestRoute("GET", "v1/exploit/search")
    def search_exploit(self, query: str, offset: int = 0):
        """API for searching exploit data with filter
        Args:
            query (str): Original searching text containing filters
            offset (int): Starting position in the dataset(entering in increments of 10)
        Returns:
            exploits (list[dict]): list of found Exploits
        TODO: pagination offset ?
        """
        params = {
            "query": query,
            "offset": offset,
        }
        # exploits = result["data"]
        return params, None, None
