from typing import Any
from typing import Dict
from typing import List
from typing import Union
from uuid import UUID

import attr
import httpx
import humps

from esetinspect.models import Detection


@attr.s
class EsetInspectClient:
    url: str = attr.ib()
    username: str = attr.ib()
    password: str = attr.ib()
    domain: bool = attr.ib(default=False)
    verify: bool = attr.ib(default=True)
    client_id: str = attr.ib(factory=str)
    timeout: int = attr.ib(default=60)
    _client: httpx.Client = attr.ib(init=False)
    _token: str = attr.ib(init=False, factory=str)

    def __attrs_post_init__(self) -> None:
        self.url = self.url.rstrip("/")

        cookies = {"CLIENT_ID": self.client_id} if self.is_cloud else {}
        self._client = httpx.Client(verify=self.verify, cookies=cookies, timeout=self.timeout)

    def _api_request(self, endpoint: str, *args: Any, method: str = "GET", **kwargs: Any) -> httpx.Response:
        uri = f"/api/v1{endpoint}"
        return self._raw_request(uri, *args, method=method, **kwargs)

    def _frontend_request(self, endpoint: str, *args: Any, method: str = "GET", **kwargs: Any) -> httpx.Response:
        uri = f"/frontend{endpoint}"
        return self._raw_request(uri, *args, method=method, **kwargs)

    def _raw_request(self, uri: str, *args: Any, method: str = "GET", **kwargs: Any) -> httpx.Response:

        if self._token != "":
            self._client.headers.update({"Authorization": f"Bearer {self._token}"})

        if method.upper() == "GET":
            http_call = self._client.get

        elif method.upper() == "POST":
            http_call = self._client.post

        elif method.upper() == "PUT":
            http_call = self._client.put

        elif method.upper() == "PATCH":
            http_call = self._client.patch

        elif method.upper() == "DELETE":
            http_call = self._client.delete

        else:
            http_call = self._client.get

        url = f"{self.url}{uri}"
        response = http_call(url, *args, **kwargs)
        response.raise_for_status()

        if "X-Security-Token" in response.headers and response.headers["X-Security-Token"] != self._token:
            self._token = response.headers.get("X-Security-Token")

        return response

    @staticmethod
    def _build_params(
        top: int = None,
        skip: int = None,
        count: bool = False,
        order_by: str = None,
        filter: str = None,
    ) -> Dict[Union[str, int], Any]:

        params: Dict[Union[str, int], Any] = dict()

        if top is not None:
            params.update({"$top": top})

        if skip is not None:
            params.update({"$skip": skip})

        if count:
            params.update({"$count": 1})

        if order_by is not None:
            params.update({"$orderby": order_by})

        if filter is not None:
            params.update({"$filter": filter})

        return params

    @staticmethod
    def _is_uuid(input: Any) -> bool:

        if isinstance(input, int):
            return False

        if isinstance(input, UUID):
            return True

        try:
            test_uuid = UUID(input)
        except ValueError:
            return False

        return str(test_uuid) == input

    def __enter__(self) -> "EsetInspectClient":
        self.login()
        return self

    def __exit__(self, *args: Any) -> None:
        self.logout()
        self._client.close()

    @property
    def is_cloud(self) -> bool:
        return self.client_id != ""

    def login(self) -> None:
        data: Dict[str, Union[str, bool]] = {"username": self.username, "password": self.password}

        if not self.is_cloud:
            data.update({"domain": self.domain})

        self.api_post("/authenticate", json=data)

    def logout(self) -> None:
        data = {"token": self._token}
        self._token = ""
        self.frontend_post("/logout", json=data)

    def api_get(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._api_request(endpoint, *args, method="GET", **kwargs)

    def api_post(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._api_request(endpoint, *args, method="POST", **kwargs)

    def api_put(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._api_request(endpoint, *args, method="PUT", **kwargs)

    def api_patch(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._api_request(endpoint, *args, method="PATCH", **kwargs)

    def api_delete(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._api_request(endpoint, *args, method="DELETE", **kwargs)

    def frontend_get(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._frontend_request(endpoint, *args, method="GET", **kwargs)

    def frontend_post(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._frontend_request(endpoint, *args, method="POST", **kwargs)

    def frontend_put(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._frontend_request(endpoint, *args, method="PUT", **kwargs)

    def frontend_delete(self, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return self._frontend_request(endpoint, *args, method="DELETE", **kwargs)

    def list_detections(
        self,
        top: int = None,
        skip: int = None,
        count: bool = False,
        order_by: str = None,
        filter: str = None,
    ) -> List[Detection]:
        """List all detections matching the specified criteria."""
        params = self._build_params(top=top, skip=skip, count=count, order_by=order_by, filter=filter)
        response = self.api_get("/detections", params=params)
        detections = [Detection(**d) for d in humps.decamelize(response.json()["value"])]
        return detections

    def get_detection(self, detection_id: int) -> Detection:
        """Get a specific detection based on ID or UUID."""
        params = {"$idType": "uuid" if self._is_uuid(detection_id) else "id"}
        response = self.api_get(f"/detections/{detection_id}", params=params)
        detection = Detection(**humps.decamelize(response.json()["DETECTION"]))
        return detection

    def update_detection(self, detection_id: int, resolved: bool = None, priority: int = None, note: str = "") -> bool:
        """Update detection details."""
        params = {"$idType": "uuid" if self._is_uuid(detection_id) else "id"}
        body: Dict[str, Union[bool, int, str]] = {"note": note}

        if resolved is not None:
            body.update({"resolved": resolved})

        if priority is not None:
            body.update({"priority": priority})

        response = self.api_patch(f"/detections/{detection_id}", params=params, json=body)
        if response.status_code == 204:
            return True
        return False
