import logging
import json
import requests
import typing
import urllib.parse

from .exceptions import ApiClientException, APIClientModelException


class ApiClient:
    def __init__(
        self,
        base_url: str,
        headers: typing.Optional[dict[str, typing.Any]] = None,
        proxies: typing.Any = None,
        verify: typing.Any = None,
    ):
        self.base_url = base_url
        self.headers = dict()
        self.proxies = proxies
        self.verify = verify

        if headers and isinstance(headers, dict):
            self.headers.update(headers)

        if "content-type" not in [header.lower() for header in self.headers.keys()]:
            self.headers["Content-Type"] = "application/json"
        if "accept" not in [header.lower() for header in self.headers.keys()]:
            self.headers["Accept"] = "application/json"


class Response:
    """Manage the response with Mode"""

    def __init__(self, model):
        if not getattr(model, "map_model"):
            raise APIClientModelException("Given model doesn't have `map_model` method")
        self.model = model

    def __call__(self, func):
        def wraps(*args, **kwargs):
            data = func(*args, **kwargs)
            m = self.model.map_model(data)
            return m

        return wraps


class RequestRoute:
    """RequestRoute"""

    def __init__(
        self,
        method: str,
        path: str,
        headers: typing.Optional[dict[str, typing.Any]] = None,
        raw_response: bool = False,
    ):
        self.method = method.upper()
        self.path = path
        self.raw_response = raw_response
        self.additional_headers = dict()
        if headers and isinstance(headers, dict):
            self.additional_headers.update(headers)

        # Set Method function
        if self.method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise ApiClientException(f"Not supported method, {self.method}")

        if self.path.startswith("/"):
            self.path = self.path[1:]

    def __call__(self, func):
        def wraps(*args, **kwargs):
            return self.call(func, *args, **kwargs)

        return wraps

    def get_path(self, func, *args, **kwargs):
        path = self.path
        idx = 0
        for keyword in self.path.split("/"):
            print(f"{self.path=}, {keyword=}, {idx=}")
            if len(keyword) > 2 and keyword[0] == "<" and keyword[-1] == ">":
                try:
                    path = path.replace(keyword, args[idx])
                except Exception:
                    raise Exception(
                        f"{func.__name__} doesn't have argument for {keyword}"
                    )
                idx += 1
        return path

    def call(self, func, *args, **kwargs):
        client: ApiClient = args[0]
        params, data, files = func(*args, **kwargs)

        path = self.get_path(func, *args, **kwargs)
        if not isinstance(data, str) and data is not None:
            data = json.dumps(data)

        endpoint: str = urllib.parse.urljoin(client.base_url, path)
        logging.debug(f"url: {endpoint}")

        # Set headers
        headers = client.headers
        if self.additional_headers:
            headers.update(self.additional_headers)
        res: requests.Response = self.request(
            self.method,
            endpoint,
            headers,
            params,
            data,
            files,
            proxies=client.proxies,
            verify=client.verify,
        )

        if res.status_code == 401 and self.reauth:
            logging.error("Error Code 401 - API Key likely incorrect")
        if not res.ok:
            raise Exception(
                f"Failed to run command uri: {endpoint}, Method: {self.method},"
                f"request status code: {res.status_code}, Body: {res.text}"
            )

        if not res.text:
            logging.info(f"Succeed but no result: {res.status_code}, {res.text}")
            return {}
        if self.raw_response:
            return res.content
        try:
            results = res.json()
        except Exception:
            raise Exception(
                f"Failed to render JSON response into Dictionary command "
                f"uri: {endpoint}, Method: {self.method}, "
                f"request status code: {res.status_code}, Body: {res.text}"
            )
        logging.debug(f"API Call result: {res.status_code}")
        return results

    def request(
        self,
        method: str,
        endpoint: str,
        headers: dict[str, typing.Any],
        params: typing.Any = None,
        data: typing.Any = None,
        files: typing.Any = None,
        proxies: typing.Any = None,
        verify: typing.Any = None,
    ) -> requests.Request:
        """Wrap the requests

        :param method: method for the new Request object: GET, POST, PUT, PATCH, or DELETE.
        :type method: str

        :param endpoint: URL for the new Request object.
        :type endpoint: str

        :param headers: Dictionary of HTTP Headers to send with the Request.
        :type headers: Dict[str, Any]

        :param params: Dictinary object to send in the body of the Request
        :type params: Dict[str, Any]

        :param data: Dictionary to send in the body of the Request
        :type data: Dict[str, Any]

        :param files: Dictionary of 'name', file-like-objects for multipart encoding upload.
        :type files: Dict[str, Any]

        :param proxies:
        :type proxies:

        :param verify:
        :type verify: bool | None | str

        :return: Response Object
        :rtype: requests.Response
        """
        if files:
            session = requests.Session()
            file_request = requests.Request(
                method, endpoint, headers=headers, files=files
            )
            prepped = file_request.prepare()
            boundary_value = prepped.body.split(b"\r\n")[0].decode()[2:]
            prepped.headers[
                "Content-Type"
            ] = f"multipart/form-data; boundary={boundary_value}"
            res = session.send(prepped, verify=verify, proxies=proxies)
        else:
            res = requests.request(
                method,
                endpoint,
                headers=headers,
                params=params,
                data=data,
                files=files,
                proxies=proxies,
                verify=verify,
            )
        return res
