"""Holds models for various sorts of data returned from the API."""
import json
from datetime import datetime
from typing import Dict
from typing import Optional
from uuid import UUID

from attrs import asdict
from attrs import define
from attrs import field
from attrs import validators

from esetinspect.functions import _to_datetime
from esetinspect.functions import _to_json
from esetinspect.functions import _to_uuid


@define(kw_only=True)
class Detection:
    """Dataclass to hold Detection data."""

    # These fields should always be populated
    computer_id: int
    computer_name: str
    computer_uuid: UUID = field(converter=_to_uuid, repr=str)
    creation_time: Optional[datetime] = field(converter=_to_datetime, repr=str)
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

    # These fields are only present for the detection list (/detections)
    rule_id: Optional[int] = field(
        default=None,
        validator=validators.optional(validators.instance_of(int)),
    )

    # These fields are only present for detection details (/detection/{id})
    handled: Optional[int] = field(
        default=None,
        validator=validators.optional(validators.instance_of(int)),
    )
    module_first_seen_locally: Optional[datetime] = field(
        default=None,
        repr=str,
        converter=_to_datetime,
        validator=validators.optional(validators.instance_of(datetime)),
    )
    module_last_executed_locally: Optional[datetime] = field(
        default=None,
        repr=str,
        converter=_to_datetime,
        validator=validators.optional(validators.instance_of(datetime)),
    )
    process_path: Optional[str] = field(
        default=None,
        converter=str,
        validator=validators.optional(validators.instance_of(str)),
    )

    # These fields are not present on versions <1.6
    event: str = field(factory=str)
    note: str = field(factory=str)

    def to_dict(self) -> Dict:
        """Return the object as a dict."""
        return asdict(self)

    def to_json(self) -> str:
        """Return the object as a JSON string."""
        return json.dumps(asdict(self), default=_to_json)


@define
class Task:
    """Dataclass to hold Task data."""

    task_uuid: UUID = field(converter=_to_uuid, repr=str)
