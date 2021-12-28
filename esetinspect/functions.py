from datetime import datetime
from typing import Union
from uuid import UUID

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
