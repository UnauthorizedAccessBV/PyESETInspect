from datetime import datetime
from typing import Optional
from typing import overload
from typing import Union
from uuid import UUID

from esetinspect.const import EMPTY_UUID
from esetinspect.const import TIMESTAMP_FORMAT


def _to_uuid(input: str) -> UUID:
    try:
        return UUID(input)
    except ValueError:
        return EMPTY_UUID


@overload
def _to_datetime(input: None) -> None:
    pass


@overload
def _to_datetime(input: str) -> datetime:
    pass


def _to_datetime(input: Optional[str]) -> Optional[datetime]:
    if input is None:
        return input

    return datetime.strptime(input, TIMESTAMP_FORMAT)


@overload
def _to_json(input: UUID) -> str:
    pass


@overload
def _to_json(input: datetime) -> datetime:
    pass


@overload
def _to_json(input: str) -> str:
    pass


def _to_json(input: Union[str, UUID, datetime]) -> Union[str, datetime]:
    if isinstance(input, UUID):
        return str(input)

    if isinstance(input, datetime):
        return datetime.strftime(input, TIMESTAMP_FORMAT)

    return input
