from __future__ import annotations

# import json
import argparse
import json
import logging
import os
import platform
from http import HTTPStatus, HTTPMethod
import re
import sys
from typing import (
    TypedDict,
    Unpack,
    Literal,
    Mapping,
    Sequence,
    Any,
    cast,
    TypeVar,
)

from deprecated import deprecated
import requests
from requests.adapters import HTTPAdapter

# from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError
from urllib3.util.retry import Retry
from urllib.parse import urlencode

# from oaaclient import __version__ as OAACLIENT_VERSION
import oaaclient.utils as oaautils
from oaaclient import __version__ as OAACLIENT_VERSION


import api_schemas as schema
from api_schemas import JSON

PROVIDER_ICON_MAX_SIZE = 64_000
PYTHON_VERSION = platform.python_version()
OS_NAME = platform.system()
OS_VERSION = platform.release()

log = logging.getLogger(__name__)

T = TypeVar("T")


class OAAClientError(Exception):
    """Error raised by OAAClient.

    Raised for issues connecting to the OAA API and when the API returns an error.

    Args:
        error (str): short string for error message
        message (str): detailed error message
        status_code (int, optional): status code for HTTP related errors. Defaults to None.
        details (list[str], optional): list of additional details for error. Defaults to None.
    """

    def __init__(
        self,
        error: str,
        message: str,
        status_code: int | None = None,
        details: list[str] | None = None,
    ) -> None:
        self.error = error
        self.message = message
        self.status_code = status_code
        self.details = details or []

        super().__init__(f"{error}: {message}")


class _OAAClientErrorKwargs(TypedDict, total=False):
    error: str
    message: str
    status_code: int | None
    details: list[str] | None


class OAAResponseError(OAAClientError):
    """Error returned from API Call"""

    def __init__(
        self,
        request_id: str | None = None,
        timestamp: str | None = None,
        **kwargs: Unpack[_OAAClientErrorKwargs],
    ):
        self.request_id = request_id
        self.timestamp = timestamp
        super().__init__(**kwargs)


class OAAConnectionError(OAAClientError):
    """Error with API Connection"""


def _get_int_env(env_var: str, default: int) -> int:
    try:
        return int(os.getenv(env_var, "NaN"))
    except ValueError:
        log.error(
            "%s variable must be integer, ignoring and setting to default %d",
            env_var,
            default,
        )
        return default


class OAAClient:
    """
    Class for OAA API Connection and Management

    Utilities for OAA-related operations with Veza API calls. Manages custom providers and data sources, and can push OAA
    payloads from JSON or template objects.

    Connection url and API key can be automatically loaded from OS environment values if set. To utilize environment variables
    initialize OAAClient without providing a URL or API key value and set the `VEZA_URL` and `VEZA_API_KEY` OS environment variables.

    Args:
        url (str, optional): URL for Veza instance
        api_key (str, optional): Veza API key
        username (str, optional): Not used (legacy). Defaults to None.
        token (str, optional): Legacy parameter name for API key. Defaults to None.

    Attributes:
        url (str): URL of the targetted Veza tenant
        api_key (str): Veza API key
        enable_compression (bool): Enable or disable compression of the OAA payload
            during push. Defaults to enabled (True)

    Raises:
        OAAClientError: For errors connecting to API and if API returns errors
    """

    DEFAULT_RETRY_COUNT = 10
    DEFAULT_RETRY_BACKOFF_FACTOR = 0.6
    DEFAULT_RETRY_MAX_BACKOFF = 30
    DEFAULT_PAGE_SIZE = 250
    DEFAULT_API_TIMEOUT = 300
    MULTIPART_THRESHOLD_SIZE = 50_000_000
    DEFAULT_PART_SIZE = 50_000_000
    MAX_PAYLOAD_SIZE = 100_000_000
    ALLOWED_CHARACTERS = r"^[ @#$%&*:()!,a-zA-Z0-9_'\"=.-]*$]"

    def __init__(
        self,
        url: str | None = os.getenv("VEZA_URL"),
        api_key: str | None = None,
        username: str | None = None,
        token: str | None = None,
    ):
        if not url:
            raise ValueError("Must provide Veza URL")

        if not re.match(r"^https:\/\/.*", url):
            self.url = f"https://{url}".rstrip("/")
        else:
            self.url = self.url.rstrip("/")
        if not self.url:
            raise OAAClientError("MISSING_URL", "URL cannot be None")

        self.api_key = api_key or token or os.getenv("VEZA_API_KEY")
        if not self.api_key:
            raise OAAClientError("MISSING_AUTH", "Must provide Veza API key")

        self.username = username

        is_unsafe = os.getenv("VEZA_UNSAFE_HTTPS", "false").lower() == "true"
        self.verify_ssl = not is_unsafe

        self.enable_compression = True
        self.enable_multipart = False

        self._api_timeout = _get_int_env(
            "DEFAULT_API_TIMEOUT", self.DEFAULT_API_TIMEOUT
        )

        retry_count = _get_int_env("OAA_API_RETRIES", self.DEFAULT_RETRY_COUNT)
        retry_policy = OAARetry(
            backoff_max=self.DEFAULT_RETRY_MAX_BACKOFF,
            total=retry_count,
            backoff_factor=self.DEFAULT_RETRY_BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_policy)
        self._http_adapter = requests.Session()
        self._http_adapter.mount("https://", adapter)
        self._http_adapter.mount("http://", adapter)

        self._user_agent = f"oaaclient/{OAACLIENT_VERSION} python/{PYTHON_VERSION} {OS_NAME}/{OS_VERSION};"
        self._test_connection()  # test connection

    def get_provider_list(self) -> list[schema.CustomProvider]:
        """
        Return list of Providers.

        Returns:
            JSON: Returns the list of existing providers
        """
        return cast(
            list[schema.CustomProvider],
            self.api_get(
                "/api/v1/providers/custom", params={"page_size": self.DEFAULT_PAGE_SIZE}
            ),
        )

    def get_provider(self, name: str) -> schema.CustomProvider | None:
        response = self.api_get(
            "/api/v1/providers/custom", params={"filter": f'name eq "{name}"'}
        )

        if not response:
            return None

        if isinstance(response, list):
            if len(response) == 1 and isinstance(response, Mapping):
                return cast(schema.CustomProvider, response[0])

        if isinstance(response, Mapping):
            ...

        log.error(response)
        raise OAAClientError(
            error="Unexpected Results",
            message="Unexpected results in response, returned more than one result",
        )

    def get_provider_by_id(self, provider_id: str) -> schema.CustomProvider | None:
        """
        Get Provider by UUID identifier.

        Args:
            provider_id (str): Unique global identifier for provider

        Returns:
            JSON: Json representation of Provider or None
        """
        try:
            response = self.api_get(f"/api/v1/providers/custom/{provider_id}")

        except OAAResponseError as error:
            if error.status_code and error.status_code == 404:
                return None
            raise error

        return cast(schema.CustomProvider, response)

    def create_provider(
        self,
        name: str,
        custom_template: str,
        base64_icon: str = "",
        options: Mapping[str, JSON] | None = None,
    ) -> schema.CustomProvider:
        if not re.match(self.ALLOWED_CHARACTERS, name):
            raise ValueError(
                f"Provider name contains invalid characters, must match {self.ALLOWED_CHARACTERS}"
            )

        data: schema.CustomProvider = {"name": name, "custom_template": custom_template}

        if options is not None:
            if isinstance(options, Mapping):  # pyright: ignore[reportUnnecessaryIsInstance]
                log.debug(
                    "Provider create called with options args: %s",
                    json.dumps(options, indent=2),
                )
                patch = cast(schema.CustomProvider, dict(options))
                data.update(patch)
            else:
                raise ValueError("options parameter must be dictionary")

        provider = self.api_post("/api/v1/provider/custom", data=data)
        if base64_icon and isinstance(provider, Mapping):  # pyright: ignore[reportUnnecessaryIsInstance]
            self.update_provider_icon(str(provider.get("id")), base64_icon)

        return provider

    def update_provider_icon(self, provider_id: str, base64_icon: str) -> None:
        if sys.getsizeof(base64_icon) > PROVIDER_ICON_MAX_SIZE:
            raise ValueError("Max icon size of 64KB exceeded")

        if isinstance(base64_icon, bytes):
            base64_icon = base64_icon.decode()

        icon_payload = {"icon_base64": base64_icon}
        self.api_post(f"/api/v1/providers/custom/{provider_id}:icon", data=icon_payload)

    def update_provisioning_status(self, provider_id: str, provisioning: bool) -> JSON:
        return self.api_patch(
            f"/api/v1/providers/custom/{provider_id}",
            data={"provisioning": provisioning},
        )

    def delete_provider(self, provider_id: str) -> JSON:
        return self.api_delete(f"/api/v1/providers/custom/{provider_id}")

    def get_data_sources(self, provider_id: str) -> JSON:
        return self.api_delete(f"/api/v1/providers/custom/{provider_id}")

    def get_data_source(self, name: str, provider_id: str) -> JSON:
        return self.api_get(
            f"/api/v1/providers/custom/{provider_id}/datasources",
            params={"filter": f'name eq "{name}"'},
        )

    def create_data_source(
        self, name: str, provider_id: str, options: dict[str, str] | None = None
    ) -> JSON:
        if not re.match(self.ALLOWED_CHARACTERS, name):
            raise ValueError(
                f"Data source name contains invalid characters, must match {self.ALLOWED_CHARACTERS}"
            )

        data_source = {"name": name, "id": provider_id}

        if options and not isinstance(options, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError("extra_args paramater must be a dictionary")

        if options:
            log.debug(f"Provider create called with extra args: {options}")
            data_source.update(options)

        return self.api_post(
            f"/api/v1/providers/custom/{provider_id}/datasources",
            data=data_source,
        )

    def delete_data_source(self, data_source_id: str, provider_id: str) -> JSON:
        return self.api_delete(
            f"/api/v1/providers/custom/{provider_id}/datasources/{data_source_id}"
        )

    def push_metadata(
        self,
        provider_name: str,
        data_source_name: str,
        metadata: object,
        save_json: bool = False,
        options: dict[str, JSON] | None = None,
    ) -> JSON:
        provider = self.get_provider(provider_name)
        if not provider:
            raise OAAClientError(
                "NO_PROVIDER",
                f"Unable to locate provder {provider_name}, cannot push without existing provider",
            )

        if not isinstance(provider, Mapping):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise OAAClientError("MALFORMED_RESPONSE", "Unexpected response structure")

        provider_id: str | None = provider.get("id")
        if not provider_id:
            raise ValueError("MALFORMED_RESPONSE", "Returned provider does not have ID")

        # data_source = self.get_data_source(data_source_name, provider_id)

    def datasource_push(
        self,
        provider_id: str,
        data_source_id: str,
        stringified_json_data: str,
        options: dict[str, str] | None = None,
    ) -> JSON: ...

    def get_queries(self, include_inactive: bool = True) -> JSON: ...

    def get_query_by_id(self, id: str) -> JSON: ...

    def create_query(self, query: Mapping[str, JSON]) -> JSON: ...

    def delete_query(self, id: str, force: bool = False) -> JSON: ...

    def get_reports(
        self,
        include_inactive_reports: bool = True,
        include_inactive_queries: bool = True,
    ) -> JSON: ...

    def get_report_by_id(self, id: str, include_inactive: bool = True) -> JSON: ...

    def create_report(self, report: Mapping[str, JSON]) -> JSON: ...

    def update_report(self, id: str, report: Mapping[str, JSON]) -> JSON: ...

    def add_query_report(self, report_id: str, query_id: str) -> JSON: ...

    def delete_report(self, id: str) -> JSON: ...

    def api_get(
        self,
        api_path: str,
        params: Mapping[str, JSON] | None = None,
    ) -> object | Sequence[object] | None:
        result: list[JSON] = []
        params = params or {}

        return result

    def api_post(
        self,
        api_path: str,
        data: T,
        params: Mapping[str, JSON] | None = None,
    ) -> schema.OAAPushAPIResponse[T]: ...

    def api_put(
        self,
        api_path: str,
        data: T,
        params: Mapping[str, JSON] | None = None,
    ) -> schema.OAAPushAPIResponse[T]: ...

    def api_patch(
        self,
        api_path: str,
        data: T,
        params: Mapping[str, JSON] | None = None,
    ) -> schema.OAAPushAPIResponse[T]: ...

    def api_delete(
        self,
        api_path: str,
        params: Mapping[str, JSON] | None = None,
    ) -> schema.OAAPushAPIResponse[object]: ...

    def _perform_request(
        self,
        method: Literal[
            HTTPMethod.GET, HTTPMethod.POST, HTTPMethod.PATCH, HTTPMethod.DELETE
        ],
        api_path: str,
        *,
        data: T | None = None,
        params: Mapping[str, JSON] | None = None,
    ) -> schema.OAAPushAPIResponse[T] | None:
        url = f"{self.url}/{api_path.lstrip('/')}"
        headers = {
            "authorization": f"Bearer {self.api_key}",
            "user-agent": self._user_agent,
        }
        params_str = urlencode(params) if params else None
        response: requests.Response | None = None

        try:
            response = self._http_adapter.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self._api_timeout,
                params=params_str,
                json=data,
                verify=self.verify_ssl,
            )
            response.raise_for_status()

            if response.status_code == HTTPStatus.NO_CONTENT or not response.content:
                return None

            payload = response.json()
            if isinstance(payload, dict):
                return cast(schema.OAAPushAPIResponse[T], payload)

            raise OAAClientError("ERROR", "Unexpected JSON shape (expected object)")

        except requests.exceptions.HTTPError as error:
            try:
                error_response = cast(dict[str, JSON], error.response.json())

            except (requests.exceptions.JSONDecodeError, ValueError):
                error_response = {}

            status_code = cast(int | None, error_response.get("status_code"))
            request_url = cast(str | None, error_response.get("url", url))
            details = cast(list[str], error_response.get("details", []) or list[str]())
            timestamp = cast(str | None, error_response.get("timestamp"))
            request_id = cast(str | None, error_response.get("request_id"))

            reason = cast(str | None, error_response.get("reason"))
            message = (
                f"Error reason: {reason}"
                if reason
                else "Unknown error, response is not JSON"
            )

            log.debug(
                "Error returned by Veza API: %s %s %s request_id: %s timestamp: %s",
                status_code,
                message,
                request_url,
                request_id,
                timestamp,
            )
            for detail in details:
                log.debug(detail)

            raise OAAResponseError(
                request_id,
                timestamp,
                error="ERROR",
                message=message,
                status_code=status_code,
                details=details,
            )

        except (requests.exceptions.JSONDecodeError, ValueError):
            status_code = response.status_code if response else None
            raise OAAClientError("ERROR", "Response not JSON", status_code=status_code)

        except requests.exceptions.RequestException as error:
            error_response = getattr(error, "response", None)
            status_code = error_response.status_code if error_response else None
            raise OAAConnectionError(
                "ERROR", message=str(error), status_code=status_code
            )

    def _test_connection(self): ...

    def update_user_agent(self, extra: str = "") -> None: ...

    @deprecated(reason="Legacy function for backward-compatibility")
    def create_datasource(self, name: str, provider_id: str) -> JSON:
        return self.create_data_source(name, provider_id)


class OAARetry(Retry):
    def __init__(self, backoff_max: int = 30, **kwargs: Any) -> None:
        super(OAARetry, self).__init__(**kwargs)
        self.DEFAULT_BACKOFF_MAX = backoff_max
        self.backoff_max = backoff_max


def report_builder_entrypoint() -> None:
    """
    Entrypoint for `oaaclient-report-builder` command

    Reads a JSON file and passes it to the `oaaclient.utils.build_report` method
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--host", default=os.getenv("VEZA_URL"), help="URL endpoint for Veza deployment"
    )
    parser.add_argument("report_file", help="Path to source report file")
    args = parser.parse_args()

    log = logging.getLogger()
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)

    report_file = args.report_file
    if not os.path.isfile(report_file):
        log.error("Unable to locate source file at path %s", report_file)
        sys.exit(1)

    try:
        report_definition = oaautils.load_json_from_file(report_file)
    except Exception as e:
        log.error(e)
        sys.exit(1)

    url = args.host
    api_key = os.getenv("VEZA_API_KEY", "")
    if not url:
        oaautils.log_arg_error(log, "--host", "VEZA_URL")
    if not api_key:
        oaautils.log_arg_error(log, None, "VEZA_API_KEY")
    if not url and api_key:
        sys.exit(1)

    veza_client = OAAClient(url, api_key=api_key)

    log.info("Loading report from %s", report_file)
    # try:
    #     oaautils.build_report(veza_client, report_definition)

    log.error(report_definition)
    log.error(veza_client)

    # TODO finish this logic after typing utils
    ...


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--auth-file", help="Config file with authentication information"
    )
    parser.add_argument("--host", help="URL endpoint for Veza deployment")
    parser.add_argument("--user", help="Username to connect as")
    parser.add_argument(
        "--provider",
        required=True,
        help="Provider definition json file, will create if doesn't exist",
    )
    parser.add_argument(
        "metadata",
        help="Metadata json file to push, uses name of file as datasource name",
    )
    args = parser.parse_args()

    auth_file = args.auth_file
    if auth_file:
        if not os.path.isfile(auth_file):
            log.error("Unable to locate auth file %s", auth_file)
            sys.exit(1)

        # auth_config = oaautils.load_json_from_file(auth_file)

        # host: str | None = auth_config.get("host")
        # _: str | None = auth_config.get("user")

        # token: str | None = auth_config.get("token")
        # _: str | None = auth_config.get("password")

        # else:
        #     host: str | None = args.host
        #     _: str | None = args.user
        #     token = None

        # provider_metadata = oaautils.load_json_from_file(args.provider)

        # provider_name = provider_metadata.get("name")
        # custom_template = provider_metadata.get("custom_template")
        # if provider_name is None or custom_template is None:
        raise Exception("Missing value in app template: name or custom_template")

    try:
        # conn = OAAClient(url=host, api_key=token)
        # provider = conn.get_provider(provider_name)
        # if provider:
        #     log.info("-- Found existing provider")
        # else:
        #     log.info(
        #         "++ Creating provider %s of type %s", provider_name, custom_template
        #     )
        #     provider = conn.create_provider(provider_name, custom_template)

        # if isinstance(provider, Mapping):
        #     log.info("-- Provider: %s (%s)", provider.get("name"), provider.get("id"))

        # data_source_name = os.path.splitext(os.path.basename(args.metadata))[0]

        # log.info("-- Pushing metadata")
        # metadata = oaautils.load_json_from_file(args.metadata)
        # response = conn.push_metadata(provider_name, data_source_name, metadata)

        # if not isinstance(response, Mapping):
        #     return

        # warnings = response.get("warnings")
        # if not warnings or not isinstance(warnings, Sequence):
        #     return

        # log.info("-- Push succeeded with warnings:")
        # for warning in warnings:
        #     log.warning("  - %s", warning)
        ...

    except OAAClientError as error:
        log.error("%s: %s (%d)", error.error, error.message, error.status_code)
        if not hasattr(error, "details"):
            return
        for detail in error.details:
            log.error("  -- %s", json.dumps(detail, indent=2))


if __name__ == "__main__":
    log = logging.getLogger(__name__)
    main()
