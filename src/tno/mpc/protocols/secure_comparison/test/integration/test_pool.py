"""
Integration tests for the tno.mpc.protocols.secure_comparison library.
"""

from __future__ import annotations

import asyncio

import pytest

from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext

from tno.mpc.protocols.secure_comparison import Initiator, KeyHolder


async def run_interactive_comparison_with_pool(
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
    initiator: Initiator,
    keyholder: KeyHolder,
) -> PaillierCiphertext:
    """
    Perform integral comparison protocol including communication
    between Initiator and KeyHolder for integration test.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input.
    :param initiator: Initiator of the secure comparison.
    :param keyholder: Keyholder in the secure comparison.
    :return: Encryption of x <= y.
    """
    task_initiator = asyncio.create_task(
        initiator.perform_secure_comparison(x_enc, y_enc)
    )
    task_keyholder = asyncio.create_task(keyholder.perform_secure_comparison())

    x_leq_y_enc, _ = await asyncio.gather(*(task_initiator, task_keyholder))
    return x_leq_y_enc


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "x, y, expected_result", ((0, 1, True), (0, 0, True), (1, 0, False))
)
async def test_pool(
    x: int,
    y: int,
    expected_result: bool,
    paillier_strict: Paillier,
    playerpair_with_pool_communication: tuple[Initiator, KeyHolder],
) -> None:
    r"""
    Validates integration with tno.mpc.communication.Pool as communicator.

    Computes $x \leq y$ using a Pool object for communication.

    :param x: First input to secure comparison.
    :param y: Second input to secure comparison.
    :param expected_result: bool($x\leq y$)
    :param paillier_strict: Paillier scheme.
    :param playerpair_with_pool_communication: Initiator-keyholder pair that
        is configured with communication.
    """
    x_enc = paillier_strict.unsafe_encrypt(x)
    y_enc = paillier_strict.unsafe_encrypt(y)
    initiator, keyholder = playerpair_with_pool_communication

    x_leq_y_enc = await run_interactive_comparison_with_pool(
        x_enc, y_enc, initiator, keyholder
    )
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)

    assert bool(x_leq_y) == expected_result
