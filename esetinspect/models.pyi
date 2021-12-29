from typing import overload
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

@overload
def _to_datetime(value: None) -> None:
    pass

@overload
def _to_datetime(value: str) -> datetime:
    pass

@overload
def _to_json(value: UUID) -> str:
    pass

@overload
def _to_json(value: datetime) -> datetime:
    pass

@overload
def _to_json(value: str) -> str:
    pass
