"""
Protocol for a communicator object.
"""

from typing import Any, Protocol


class Communicator(Protocol):
    async def send(self, party_id: str, message: Any, msg_id: str) -> None: ...

    async def recv(self, party_id: str, msg_id: str) -> Any: ...
