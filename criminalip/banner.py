from typing import Any
from criminalip.CriminalIP import Client


class Banner(Client):
    def search(self, query: str, offset: int = 0) -> dict[str, Any]:
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
        result = self.request("GET", "banner/search", params=params)
        return result["data"]

    def stats(self, query: str) -> dict[str, Any]:
        """API for providing statistics from banner_data search
        Args:
            query (str): Original searching text containing filters
        Returns:
            stats (dict[str, Any]): Stats
        """
        result = self.request("GET", "banner/stats", params={"query": query})
        return result["data"]
