import requests

import logging
from typing import Dict, List, Any, Optional, Tuple


logger = logging.getLogger("criminalip")


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
        if not api_key:
            raise CIPException("api_key is required")
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
        if data["status"] == 403:
            raise CIPLimitExcceed(data["message"])
        elif data["status"] != 200:
            raise CIPException(
                f"Failed to request, API status: {data['status']}, {data}, url: {url}"
            )
        return response.json()

    def get_user(self) -> Dict[str, Any]:
        """Get user data

        Returns:
            user_data (Dict[str, Any]): User data
        """
        result = self.request("POST", "user/me")
        user_data = result["data"]
        return user_data
