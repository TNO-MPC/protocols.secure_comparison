"""
Integration tests for the tno.mpc.protocols.secure_comparison library.
"""

import asyncio
from typing import Tuple

import pytest

from tno.mpc.communication import Pool
from tno.mpc.communication.test import (  # pylint: disable=unused-import
    event_loop,
    fixture_pool_http_2p,
)
from tno.mpc.encryption_schemes.dgk import DGK
from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
from tno.mpc.encryption_schemes.utils import next_prime

from tno.mpc.protocols.secure_comparison import Initiator, KeyHolder

BIT_LENGTH = 16

# Setting up the encryption schemes.
scheme_paillier = Paillier.from_security_parameter(key_length=1024, nr_of_threads=0)
paillier_n = scheme_paillier.public_key.n
u = next_prime((1 << (BIT_LENGTH + 2)))

# Sometimes we want full decryption to make checks.
scheme_dgk_not_full = DGK.from_security_parameter(
    v_bits=20, n_bits=128, u=u, full_decryption=False
)


async def run_interactive_comparison_with_pool(
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
    pool_http_2p: Tuple[Pool, Pool],
) -> PaillierCiphertext:
    """
    Perform integral comparison protocol including communication
    between Initiator and KeyHolder for integration test.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input.
    :param pool_http_2p: Communication pools to use.
    :return: Encryption of x <= y.
    """
    # new instances since they require shutting down the pools every time to avoid port collisions
    communicator_initiator = pool_http_2p[0]
    communicator_keyholder = pool_http_2p[1]
    initiator_id = next(iter(communicator_keyholder.pool_handlers))
    keyholder_id = next(iter(communicator_initiator.pool_handlers))

    initiator = Initiator(
        BIT_LENGTH,
        communicator=communicator_initiator,
        other_party=keyholder_id,
        scheme_paillier=scheme_paillier,
        scheme_dgk=scheme_dgk_not_full,
    )
    keyholder = KeyHolder(
        BIT_LENGTH,
        communicator=communicator_keyholder,
        other_party=initiator_id,
        scheme_paillier=scheme_paillier,
        scheme_dgk=scheme_dgk_not_full,
    )

    task_initiator = asyncio.create_task(
        initiator.perform_secure_comparison(x_enc, y_enc)
    )
    task_keyholder = asyncio.create_task(keyholder.perform_secure_comparison())

    x_leq_y_enc, _ = await asyncio.gather(*(task_initiator, task_keyholder))

    return x_leq_y_enc


@pytest.mark.parametrize(
    "x, y, expected_result", ((0, 1, True), (0, 0, True), (1, 0, False))
)
@pytest.mark.asyncio
async def test_pool(
    x: int, y: int, expected_result: bool, pool_http_2p: Tuple[Pool, Pool]
) -> None:
    r"""
    Validates integration with tno.mpc.communication.Pool as communicator.

    Computes $x \leq y$ using a Pool object for communication.

    :param x: First input to secure comparison.
    :param y: Second input to secure comparison.
    :param expected_result: bool($x\leq y$)
    :param pool_http_2p: Communication pools to use.
    """
    x_enc = scheme_paillier.unsafe_encrypt(x)
    y_enc = scheme_paillier.unsafe_encrypt(y)

    x_leq_y_enc = await run_interactive_comparison_with_pool(x_enc, y_enc, pool_http_2p)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)

    assert bool(x_leq_y) == expected_result
