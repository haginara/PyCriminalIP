from typing import Any
from criminalip.CriminalIP import Client


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
        scan_id = result["data"]["scan_id"]
        return scan_id

    def reports(self, query: str, offset: int = 0) -> dict[str, Any]:
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
        result = self.request("GET", "domain/reports", params=params)
        reports = result["data"]["reports"]
        return reports

    def report(self, scan_id: int) -> dict[str, Any]:
        """Get Domain scan result

        Args:
            scan_id (str): Scan Id for request
        Returns:
            domain_scan_result (dict[str, Any])
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
