# api_client/apiclient.py
import inspect
import json
import logging
import typing
import urllib.parse
from functools import wraps

import requests

logger = logging.getLogger("api_client")


class ApiClientException(Exception):
    pass


class APIClientModelException(Exception):
    pass


class ApiClient:
    def __init__(
        self,
        base_url: str,
        headers: typing.Optional[typing.Dict[str, typing.Any]] = None,
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

    def return_params(self, params=None, data=None, files=None):
        return (params, data, files)


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


def response(func: typing.Callable = None):
    def decorator(f):
        @wraps(f)
        def inner(*args, **kwargs):
            data = f(*args, **kwargs)
            _data = func(data)
            if _data is None:
                raise APIClientModelException(f"No expected data, {data}")
            return _data
        return inner
    return decorator


class RequestRoute:
    """RequestRoute"""

    def __init__(
        self,
        method: str,
        path: str,
        headers: typing.Optional[typing.Dict[str, typing.Any]] = None,
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

    def get_path_params(self) -> typing.List[str]:
        """Extract the params from the self.path"""
        params = []
        i = 0
        len_path = len(self.path)
        while i < len_path:
            if self.path[i] == "<":
                j = i
                while j < len_path:
                    if self.path[j] == ">":
                        param = self.path[i + 1:j]
                        logger.debug(f"Param: {param}")
                        params.append(param)
                        break
                    j += 1
                i = j
            else:
                i += 1
        return params

    def get_path(self, func, *args, **kwargs):
        """Generate the path with arguments"""
        path = self.path
        bound = inspect.signature(func).bind(*args, **kwargs)
        logger.debug(bound.arguments)

        params = self.get_path_params()
        for param in params:
            value = bound.arguments.get(param)
            if not value:
                raise ApiClientException(f"No param provided, {param}")
            path = path.replace(f"<{param}>", str(value))
            logger.debug(f"Updated: {path=}")
        return path

    def call(self, func, *args, **kwargs):  # noqa: C901
        """Inner decorator function to call the requests.request

        :param func: decorated function
        :param *args: Requested arguments from decorated funcation
        :type *args: list[Any]
        :param **kwargs: Requested key-value arguments from decorated function
        :type **kwargs: Dict[str, Any]

        :return: raw content or dict
        :rtype: str | dict[str, Any]
        """
        client: ApiClient = args[0]
        # Call decorated function to get params, data, files
        # Decorated function should return (params, data, files)
        try:
            params, data, files = func(*args, **kwargs)
        except ValueError:
            raise ApiClientException(
                "Decoreated function should return (params, data, files)"
            )
        if not isinstance(data, str) and data is not None:
            data = json.dumps(data)

        if not (files is None or isinstance(params, dict)):
            raise ValueError("params should dict, or None type")

        if not (files is None or isinstance(files, dict)):
            raise ValueError("files should dict, or None type")

        path = self.get_path(func, *args, **kwargs)
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
        headers: typing.Dict[str, typing.Any],
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


class POST(RequestRoute):
    def __init__(self, path, headers, raw_response=False):
        super(POST, self).__init__("POST", path, headers, raw_response)


class GET(RequestRoute):
    def __init__(self, path, headers, raw_response=False):
        super(POST, self).__init__("GET", path, headers, raw_response)


class PUT(RequestRoute):
    def __init__(self, path, headers, raw_response=False):
        super(POST, self).__init__("PUT", path, headers, raw_response)


class DELETE(RequestRoute):
    def __init__(self, path, headers, raw_response=False):
        super(POST, self).__init__("DELETE", path, headers, raw_response)


class HEAD(RequestRoute):
    def __init__(self, path, headers, raw_response=False):
        super(POST, self).__init__("HEAD", path, headers, raw_response)
