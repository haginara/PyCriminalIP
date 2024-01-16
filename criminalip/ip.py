from typing import Any
from criminalip.CriminalIP import Client


class IP(Client):
    def data(self, ip: str, is_full: bool = False) -> dict[str, Any]:
        """Get Ip information

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
        result = self.request("GET", "ip/data", params=params)
        return result

    def summary(self, ip: str):
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
        result = self.request("GET", "ip/summary", params=params)
        return result

    def vpn(self, ip: str):
        """Get Ip information

        Args:
            ip (str): IP address
        Returns:
            ip_data (dict[str, Any]): IP information
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
            ip_data (dict[str, Any]): IP information
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
            ip_data (dict[str, Any]): IP information
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
            ip_data (dict[str, Any]): IP information
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
            ip_data (dict[str, Any]): IP information
        """
        params = {
            "ip": ip,
        }
        result = self.request("GET", "feature/ip/is_safe_dns_server", params=params)
        return result
