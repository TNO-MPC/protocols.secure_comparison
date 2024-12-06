"""
Pytest fixtures.
"""

# pylint: disable=redefined-outer-name
from __future__ import annotations

import asyncio
import warnings
from collections.abc import Iterator
from typing import Any

import pytest

from tno.mpc.communication import Pool, Serialization
from tno.mpc.encryption_schemes.dgk import DGK
from tno.mpc.encryption_schemes.paillier import Paillier
from tno.mpc.encryption_schemes.utils import next_prime

from tno.mpc.protocols.secure_comparison import Communicator, Initiator, KeyHolder

COMPARISON_BIT_LENGTH = 16
PAILLIER_MIN_KEY_LENGTH = 1024


@pytest.fixture
def _error_on_encryption_scheme_warnings() -> Iterator[None]:
    """
    Wrapper that turns encryption scheme warnings into errors.

    :return: Context with custom warningfilters.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings("error", ".*ciphertext", UserWarning)
        warnings.filterwarnings("error", ".*randomness", UserWarning)
        yield


@pytest.fixture
def paillier_strict(_error_on_encryption_scheme_warnings: None) -> Iterator[Paillier]:
    """
    Yields a Paillier encryption scheme and properly shuts it down afterwards.

    This fixture will promote encryption scheme warnings into errors (e.g. it is "strict").

    :return: Paillier encryption scheme.
    """
    # _error_on_encryption_scheme_warnings fixture promotes selected warnings into errors
    paillier = Paillier.from_security_parameter(key_length=PAILLIER_MIN_KEY_LENGTH)
    yield paillier
    paillier.shut_down()


@pytest.fixture
def dgk_not_full_strict(_error_on_encryption_scheme_warnings: None) -> Iterator[DGK]:
    """
    Yields a DGK encryption scheme without full decryption and properly shuts
    it down afterwards.

    This fixture will promote encryption scheme warnings into errors (e.g. it is "strict").

    :return: DGK encryption scheme without full decryption.
    """
    # _error_on_encryption_scheme_warnings fixture promotes selected warnings into errors
    u = next_prime(1 << (COMPARISON_BIT_LENGTH + 2))
    dgk = DGK.from_security_parameter(v_bits=20, n_bits=128, u=u, full_decryption=False)
    yield dgk
    dgk.shut_down()


@pytest.fixture
def alice() -> Initiator:
    """
    Initiator for the secure comparison protocol with full DGK decryption.

    :return: Initiator.
    """
    return make_initiator(COMPARISON_BIT_LENGTH)


@pytest.fixture
def bob_not_full(paillier_strict: Paillier, dgk_not_full_strict: DGK) -> KeyHolder:
    """
    Keyholder for the secure comparison protocol without full DGK decryption.

    :param paillier_strict: Paillier scheme.
    :param dgk_not_full_strict: DGK scheme without full decryption.
    :return: Keyholder.
    """
    return make_keyholder(
        COMPARISON_BIT_LENGTH,
        paillier_strict,
        dgk_not_full_strict,
    )


@pytest.fixture
def playerpair_with_pool_communication(
    http_pool_duo: tuple[Pool, Pool],
    paillier_strict: Paillier,
    dgk_not_full_strict: DGK,
) -> tuple[Initiator, KeyHolder]:
    """
    Fixture for a secure comparison player pair. The players communicate
    through an http pool.

    :param http_pool_duo: Communication pools.
    :param paillier_strict: Paillier scheme.
    :param dgk_not_full_strict: DGK scheme.
    :return: Initiator and KeyHolder for secure comparison. The players
        communicate through http.
    """
    communicator_initiator = http_pool_duo[0]
    communicator_keyholder = http_pool_duo[1]
    initiator_id = next(iter(communicator_keyholder.pool_handlers))
    keyholder_id = next(iter(communicator_initiator.pool_handlers))

    initiator = make_initiator(
        COMPARISON_BIT_LENGTH,
        communicator=communicator_initiator,
        other_party=keyholder_id,
    )
    keyholder = make_keyholder(
        COMPARISON_BIT_LENGTH,
        paillier_strict,
        dgk_not_full_strict,
        communicator=communicator_keyholder,
        other_party=initiator_id,
    )
    return initiator, keyholder


@pytest.fixture
def playerpair_with_dict_communication(
    paillier_strict: Paillier,
    dgk_not_full_strict: DGK,
) -> tuple[Initiator, KeyHolder]:
    """
    Fixture for a secure comparison player pair. The players communicate
    through a dictionary.

    :param paillier_strict: Paillier scheme.
    :param dgk_not_full_strict: DGK scheme.
    :return: Initiator and KeyHolder for secure comparison. The players
        communicate through a dictionary.
    """
    communicator = DictionaryCommunicator()

    initiator = make_initiator(
        COMPARISON_BIT_LENGTH,
        communicator=communicator,
    )
    keyholder = make_keyholder(
        COMPARISON_BIT_LENGTH,
        paillier_strict,
        dgk_not_full_strict,
        communicator=communicator,
    )
    return initiator, keyholder


class DictionaryCommunicator:
    """
    Simple communicator based on a dictionary.
    """

    def __init__(self) -> None:
        """
        Initializes a dictionary communicator.
        """
        self.dict: dict[str, Any] = {}

    async def send(self, party_id: str, message: Any, msg_id: str) -> None:
        """
        Send a message to the other party.

        :param party_id: ID of the receiving party.
        :param message: Message to be send.
        :param msg_id: ID of the message.
        """
        del party_id
        message = Serialization.pack(message, msg_id=msg_id, use_pickle=False)
        self.dict[msg_id] = message

    async def recv(self, party_id: str, msg_id: str) -> Any:
        """
        Receive a message from the other party.

        :param party_id: ID of the receiving party.
        :param msg_id: ID of the message.
        :return: The contents of the message.
        """
        del party_id
        for _ in range(1_000):
            if not msg_id in self.dict:
                await asyncio.sleep(0.001)
        obj = self.dict.pop(msg_id)
        return Serialization.unpack(obj)[1]


def make_initiator(
    bit_length: int,
    communicator: Communicator | None = None,
    other_party: str = "",
) -> Initiator:
    """
    Helper function to create an initiator.

    :param bit_length: Maximum bit length of plaintext inputs to the secure
        comparison.
    :param communicator: Communication instance.
    :param other_party: ID of the other party.
    :return: Initiator.
    """
    return Initiator(
        l_maximum_bit_length=bit_length,
        communicator=communicator,
        other_party=other_party,
    )


def make_keyholder(
    bit_length: int,
    paillier_scheme: Paillier,
    dgk_scheme: DGK,
    communicator: Communicator | None = None,
    other_party: str = "",
) -> KeyHolder:
    """
    Helper function to create a keyholder.

    :param bit_length: Maximum bit length of plaintext inputs to the secure
        comparison.
    :param paillier_scheme: Paillier scheme.
    :param dgk_scheme: DGK scheme.
    :param communicator: Communication instance.
    :param other_party: ID of the other party.
    :return: Keyholder.
    """
    return KeyHolder(
        l_maximum_bit_length=bit_length,
        scheme_paillier=paillier_scheme,
        scheme_dgk=dgk_scheme,
        communicator=communicator,
        other_party=other_party,
    )
