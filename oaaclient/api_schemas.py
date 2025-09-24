from collections.abc import Mapping, Sequence
from typing import TypedDict, Generic, TypeVar, TypeAlias


T = TypeVar("T")
JSON: TypeAlias = (
    Mapping[str, "JSON"] | Sequence["JSON"] | str | int | float | bool | None
)


class DestinationDatasource(TypedDict, total=False):
    type: str | None
    oaa_app_type: str | None


class IdMatcher(TypedDict, total=False):
    source_id: str | None
    destination_id: str | None


class PropertyMatcher(TypedDict, total=False):
    source_property: int | None
    destination_property: int | None
    custom_source_property: str | None
    custom_destination_property: str | None


class HrisIdentityMap(TypedDict, total=False):
    destination_datasource_type: str | None
    destination_datasource_oaa_app_type: str | None
    type: int | None
    mode: int | None
    transformations: list[int]
    custom_value: str | None
    property_matchers: list[PropertyMatcher] | None
    id_matchers: list[IdMatcher] | None
    destination_datasources: list[DestinationDatasource] | None


class HrisIdentityMapping(TypedDict, total=False):
    mappings: list[HrisIdentityMap] | None
    use_email: bool | None


class Hris(TypedDict, total=False):
    hris_name: str | None
    hris_type: str | None
    hris_url: str | None
    hris_identity_mapping: HrisIdentityMapping | None
    hris_provisioning_source: bool | None


class SecretReference(TypedDict, total=False):
    secret_id: str | None
    vault_id: str | None


class Idp(TypedDict, total=False):
    idp_type: str | None
    domain: str | None


class Advanced(TypedDict, total=False):
    list_delimiter: str | None


class Application(TypedDict, total=False):
    application_name: str | None
    application_type: str | None
    identity: list[str] | None
    resource_type: str | None


class CustomProperty(TypedDict, total=False):
    name: str | None
    type: int | None
    lcm_unique_identifier: bool | None


class CsvColumnMapping(TypedDict, total=False):
    column_name: str | None
    destination_type: str | None
    destination_property: str | None
    custom_property: CustomProperty | None
    as_list: bool | None


class CsvMappingConfiguration(TypedDict, total=False):
    template_type: str | None
    column_mappings: list[CsvColumnMapping] | None
    application: Application | None
    advanced: Advanced | None
    idp: Idp | None
    hris: Hris | None


class CustomProvider(TypedDict, total=False):
    name: str | None
    custom_template: str | None
    provisioning: bool | None
    push_type: int | None
    internal_app_name: str | None
    configuration_json: str | None
    data_plane_id: str | None
    custom_templates: list[str] | None
    csv_mapping_configuration: CsvMappingConfiguration | None
    secret_references: list[SecretReference] | None


class CustomProviderResponse(TypedDict):
    id: str | None
    external_id: str | None
    name: str | None
    custom_template: str | None
    custom_templates: list[str] | None
    state: int | None
    application_types: list[str] | None
    idp_types: list[str] | None
    file_system_types: list[str] | None
    hris_types: list[str] | None
    principal_types: list[str] | None
    schema_definition_json: str | None
    provisioning: bool | None
    push_type: int | None
    rbac_id: str | None
    internal_app_name: str | None
    configuration_json: str | None
    data_plane_id: str | None
    lifecycle_management_state: int | None
    team_id: str | None
    csv_mapping_configuration: CsvMappingConfiguration | None
    secret_references: list[SecretReference] | None


class OAAPushAPIResponse(TypedDict, Generic[T], total=False):
    value: T


class OAAPushAPIErrorResponse(TypedDict, total=False):
    code: int
    message: str
    details: JSON
