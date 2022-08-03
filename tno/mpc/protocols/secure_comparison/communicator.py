import sys
from typing import Any

if sys.version_info >= (3, 8):
    from typing import Protocol
else:
    from typing_extensions import Protocol


class Communicator(Protocol):
    async def send(self, party_id: str, message: Any, msg_id: str) -> None:
        ...

    async def recv(self, party_id: str, msg_id: str) -> Any:
        ...
