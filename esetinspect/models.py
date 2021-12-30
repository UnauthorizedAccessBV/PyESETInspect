"""Holds models for various sorts of data returned from the API."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional
from typing import overload
from typing import Union
from uuid import UUID
from xml.etree.ElementTree import Element  # nosec - only used for type checking

from attrs import asdict
from attrs import converters
from attrs import define
from attrs import field
from defusedxml import ElementTree as ET
from humps import decamelize

from esetinspect.const import EMPTY_UUID
from esetinspect.const import TIMESTAMP_FORMAT


def _to_uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError:
        return EMPTY_UUID


@overload
def _to_datetime(value: None) -> None:
    pass


@overload
def _to_datetime(value: str) -> datetime:
    pass


def _to_datetime(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None

    retval = datetime.strptime(value, TIMESTAMP_FORMAT)
    return retval


@overload
def _to_json(value: UUID) -> str:
    pass


@overload
def _to_json(value: datetime) -> datetime:
    pass


@overload
def _to_json(value: str) -> str:
    pass


@overload
def _to_json(value: Element) -> str:
    pass


def _to_json(value: Union[str, UUID, datetime, Element]) -> Union[str, datetime]:
    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, datetime):
        return datetime.strftime(value, TIMESTAMP_FORMAT)

    if isinstance(value, Element):
        retval: str = _xml_to_str(value)
        return retval

    return value


def _to_detections(value: dict) -> list[Detection]:
    retval = [Detection(**d) for d in decamelize(value)]
    return retval


def _to_rules(value: dict) -> list[Rule]:
    retval = [Rule(**r) for r in decamelize(value)]
    return retval


@overload
def _to_xml(value: str) -> Element:
    pass


@overload
def _to_xml(value: None) -> None:
    pass


def _to_xml(value: Optional[str]) -> Optional[Element]:
    if value is None:
        return None

    retval: Element = ET.fromstring(value)
    return retval


@overload
def _xml_to_str(value: None) -> None:
    pass


@overload
def _xml_to_str(value: Element) -> str:
    pass


def _xml_to_str(value: Optional[Element]) -> Optional[str]:
    if value is None:
        return None

    retval: str = ET.tostring(value).decode()
    return retval


@define(kw_only=True)
class Detection:
    """Dataclass to hold Detection data."""

    # These fields should always be populated
    computer_id: int
    computer_name: str
    computer_uuid: UUID = field(converter=_to_uuid, repr=str)
    # BUG: https://github.com/python-attrs/attrs/issues/897
    creation_time: datetime = field(converter=_to_datetime, repr=str)  # type: ignore
    id: int
    module_id: int
    module_lg_age: int
    module_lg_popularity: int
    module_lg_reputation: int
    module_name: str
    module_sha1: str
    module_signature_type: int
    module_signer: str
    priority: int
    process_command_line: str
    process_id: int
    process_user: str
    resolved: bool
    rule_name: str
    rule_uuid: UUID = field(converter=_to_uuid, repr=str)
    severity: int
    severity_score: int
    threat_name: str
    threat_uri: str
    type: int
    uuid: UUID = field(converter=_to_uuid, repr=str)

    # These fields are not present on versions <1.6
    event: Optional[str] = field(default=None, converter=converters.optional(str))
    note: Optional[str] = field(default=None, converter=converters.optional(str))

    # These fields are only present for the detection list (/detections)
    rule_id: Optional[int] = field(default=None, converter=converters.optional(int))

    # These fields are only present for detection details (/detection/{id})
    handled: Optional[int] = field(default=None, converter=converters.optional(int))
    # BUG: https://github.com/python-attrs/attrs/issues/897
    module_first_seen_locally: Optional[datetime] = field(  # type: ignore
        default=None, repr=str, converter=converters.optional(_to_datetime)
    )
    # BUG: https://github.com/python-attrs/attrs/issues/897
    module_last_executed_locally: Optional[datetime] = field(  # type: ignore
        default=None, repr=str, converter=converters.optional(_to_datetime)
    )
    process_path: Optional[str] = field(default=None, converter=converters.optional(str))

    def to_dict(self) -> dict:
        """Return the object as a dict."""
        retval: dict = asdict(self)
        return retval

    def to_json(self) -> str:
        """Return the object as a JSON string."""
        retval = json.dumps(asdict(self), default=_to_json)
        return retval


@define(kw_only=True)
class DetectionList:
    """Dataclass to hold a list of detection objects."""

    value: list[Detection] = field(converter=_to_detections)
    count: Optional[int] = field(default=None, converter=converters.optional(int))


@define(kw_only=True)
class Task:
    """Dataclass to hold Task data."""

    task_uuid: UUID = field(converter=_to_uuid, repr=str)


@define(kw_only=True)
class Rule:
    """Dataclass to huld a rule object."""

    # These fields are always populated
    enabled: bool
    id: int
    name: str
    severity: int
    severity_score: int

    # These fields are only present when getting rule details
    # BUG: https://github.com/python-attrs/attrs/issues/897
    body: Optional[Element] = field(  # type: ignore
        default=None, converter=converters.optional(_to_xml), repr=_xml_to_str
    )
    uuid: Optional[UUID] = field(default=None, converter=converters.optional(_to_uuid), repr=str)

    def to_dict(self) -> dict:
        """Return the object as a dict."""
        retval: dict = asdict(self)
        return retval

    def to_json(self) -> str:
        """Return the object as a JSON string."""
        retval = json.dumps(asdict(self), default=_to_json)
        return retval


@define(kw_only=True)
class RuleList:
    """Dataclass to hold a list of rule objects."""

    value: list[Rule] = field(converter=_to_rules)
    count: Optional[int] = field(default=None, converter=converters.optional(int))
