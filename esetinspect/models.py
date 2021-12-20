"""Holds models for various sorts of data returned from the API."""
import json
from datetime import datetime
from typing import Dict
from typing import Optional
from typing import Union
from uuid import UUID

import attr

from esetinspect.const import EMPTY_UUID
from esetinspect.const import TIMESTAMP_FORMAT


def _to_uuid(input: str) -> UUID:
    try:
        return UUID(input)
    except ValueError:
        return EMPTY_UUID


def _to_datetime(input: Union[str, None]) -> Union[datetime, None]:
    if input is not None:
        return datetime.strptime(input, TIMESTAMP_FORMAT)
    return input


def _to_json(input: Union[str, UUID, datetime]) -> str:
    if isinstance(input, UUID):
        return str(input)

    if isinstance(input, datetime):
        return datetime.strftime(input, TIMESTAMP_FORMAT)

    return input


@attr.s(kw_only=True)
class Detection:
    """Dataclass to hold Detection data."""

    # These fields should always be populated
    computer_id: int = attr.ib()
    computer_name: str = attr.ib()
    computer_uuid: UUID = attr.ib(converter=_to_uuid, repr=str)
    creation_time: Optional[datetime] = attr.ib(converter=_to_datetime, repr=str)
    id: int = attr.ib()
    module_id: int = attr.ib()
    module_lg_age: int = attr.ib()
    module_lg_popularity: int = attr.ib()
    module_lg_reputation: int = attr.ib()
    module_name: str = attr.ib()
    module_sha1: str = attr.ib()
    module_signature_type: int = attr.ib()
    module_signer: str = attr.ib()
    priority: int = attr.ib()
    process_command_line: str = attr.ib()
    process_id: int = attr.ib()
    process_user: str = attr.ib()
    resolved: bool = attr.ib()
    rule_name: str = attr.ib()
    rule_uuid: UUID = attr.ib(converter=_to_uuid, repr=str)
    severity: int = attr.ib()
    severity_score: int = attr.ib()
    threat_name: str = attr.ib()
    threat_uri: str = attr.ib()
    type: int = attr.ib()
    uuid: UUID = attr.ib(converter=_to_uuid, repr=str)

    # These fields are only present for the detection list (/detections)
    rule_id: Optional[int] = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )

    # These fields are only present for detection details (/detection/{id})
    handled: Optional[int] = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )
    module_first_seen_locally: Optional[datetime] = attr.ib(
        default=None,
        repr=str,
        converter=_to_datetime,
        validator=attr.validators.optional(attr.validators.instance_of(datetime)),
    )
    module_last_executed_locally: Optional[datetime] = attr.ib(
        default=None,
        repr=str,
        converter=_to_datetime,
        validator=attr.validators.optional(attr.validators.instance_of(datetime)),
    )
    process_path: Optional[str] = attr.ib(
        default=None,
        converter=str,
        validator=attr.validators.optional(attr.validators.instance_of(str)),
    )

    # These fields are not present on versions <1.6
    event: str = attr.ib(factory=str)
    note: str = attr.ib(factory=str)

    def to_dict(self) -> Dict:
        """Return the object as a dict."""
        return attr.asdict(self)

    def to_json(self) -> str:
        """Return the object as a JSON string."""
        return json.dumps(attr.asdict(self), default=_to_json)
