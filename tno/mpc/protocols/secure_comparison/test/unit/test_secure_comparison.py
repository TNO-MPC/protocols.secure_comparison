"""
Unit tests for the tno.mpc.protocols.secure_comparison library.
"""

import asyncio
from math import ceil, log
from typing import Any, Dict, List, cast

import pytest

from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.dgk import DGK, DGKCiphertext
from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
from tno.mpc.encryption_schemes.utils import next_prime

from tno.mpc.protocols.secure_comparison import Initiator, KeyHolder, from_bits, to_bits

test_vals_smaller_plaintext = [
    230,
    679,
    1084,
    1428,
    1508,
    1915,
    2606,
    3039,
    3122,
    3852,
    4075,
    4185,
    4250,
    4938,
    5746,
    6240,
    8668,
    9451,
    9612,
    9909,
]

test_vals_bigger_plaintext = [
    269,
    854,
    1814,
    2333,
    2408,
    4110,
    5019,
    5710,
    6048,
    6451,
    6587,
    6887,
    7804,
    8200,
    8237,
    8585,
    9015,
    9729,
    9766,
    9934,
]

BIT_LENGTH = 16

# Setting up the communication handler
communication_dict: Dict[str, Any] = dict()


class DictionaryCommunicator:
    """
    Simple communicator based on a dictionary.
    """

    def __init__(self, dictionary: Dict[str, Any]) -> None:
        self.dict = dictionary

    async def send(self, party_id: str, message: Any, msg_id: str) -> None:
        del party_id
        message = Serialization.pack(message, msg_id=msg_id, use_pickle=False)
        self.dict[msg_id] = message

    async def recv(self, party_id: str, msg_id: str) -> Any:
        del party_id
        for _ in range(1_000):
            if not msg_id in self.dict:
                await asyncio.sleep(0.001)
        obj = self.dict.pop(msg_id)
        return Serialization.unpack(obj)[1]


communicator_alice = communicator_bob = DictionaryCommunicator(communication_dict)

# Setting up the encryption schemes.
scheme_paillier = Paillier.from_security_parameter(key_length=1024, nr_of_threads=0)
paillier_n = scheme_paillier.public_key.n
u = next_prime((1 << (BIT_LENGTH + 2)))

# Sometimes we want full decryption to make checks.
scheme_dgk_full = DGK.from_security_parameter(
    v_bits=20, n_bits=128, u=u, full_decryption=True
)
scheme_dgk_not_full = DGK.from_security_parameter(
    v_bits=20, n_bits=128, u=u, full_decryption=False
)

# Initializing the test inputs.

alice = Initiator(
    BIT_LENGTH,
    scheme_paillier=scheme_paillier,
    scheme_dgk=scheme_dgk_full,
)
bob = KeyHolder(
    BIT_LENGTH,
    scheme_paillier=scheme_paillier,
    scheme_dgk=scheme_dgk_full,
)

test_vals_smaller = list(
    map(scheme_paillier.unsafe_encrypt, test_vals_smaller_plaintext)
)
test_vals_bigger = list(map(scheme_paillier.unsafe_encrypt, test_vals_bigger_plaintext))
test_conversion_to_bool = [
    (test_vals_smaller[0], test_vals_bigger[0], True),
    (test_vals_bigger[0], test_vals_smaller[0], False),
    (test_vals_bigger[0], test_vals_bigger[0], True),
]
test_constraints_l = [
    (
        test_vals_smaller_plaintext[0],
        test_vals_bigger_plaintext[0],
        test_vals_smaller[0],
        test_vals_bigger[0],
        BIT_LENGTH,
        False,
    ),
    (
        test_vals_smaller_plaintext[0],
        test_vals_bigger_plaintext[0],
        test_vals_smaller[0],
        test_vals_bigger[0],
        ceil(log(scheme_paillier.public_key.n, 2)),
        True,
    ),
    (
        test_vals_smaller_plaintext[0],
        test_vals_bigger_plaintext[0],
        test_vals_smaller[0],
        test_vals_bigger[0],
        ceil(log(scheme_paillier.public_key.n, 2)) - 1,
        True,
    ),
]
test_4a = [
    (0),
    (paillier_n),
    ((paillier_n - 1) // 2),
]
test_4c = [
    (scheme_dgk_full.unsafe_encrypt(0, apply_encoding=False), 100, 0, False),
    (scheme_dgk_full.unsafe_encrypt(1, apply_encoding=False), 100, 0, False),
    (
        scheme_dgk_full.unsafe_encrypt(0, apply_encoding=False),
        paillier_n - 100,
        0,
        False,
    ),
    (
        scheme_dgk_full.unsafe_encrypt(1, apply_encoding=False),
        paillier_n - 100,
        1,
        False,
    ),
    (scheme_dgk_full.unsafe_encrypt(1, apply_encoding=False), -100, 1, True),
    (scheme_dgk_full.unsafe_encrypt(1, apply_encoding=False), 0, 0, False),
]
test_4d = [
    (to_bits(12345, BIT_LENGTH), to_bits(23456, BIT_LENGTH)),
    (to_bits(25, BIT_LENGTH), to_bits(890, BIT_LENGTH)),
]
test_5 = [
    (scheme_paillier.public_key.n, 0),
    (100, 0),
    (scheme_paillier.public_key.n, 1),
    (100, 1),
]
test_6 = [
    (0, scheme_paillier.unsafe_encrypt(0, apply_encoding=False)),
    (0, scheme_paillier.unsafe_encrypt(1, apply_encoding=False)),
    (1, scheme_paillier.unsafe_encrypt(0, apply_encoding=False)),
    (1, scheme_paillier.unsafe_encrypt(1, apply_encoding=False)),
]


def run_comparison(
    x_enc: PaillierCiphertext, y_enc: PaillierCiphertext
) -> PaillierCiphertext:
    """
    Perform integral comparison protocol for integration test.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input.
    :return: Encryption of x <= y.
    """

    z_enc, r = alice.step_1(x_enc, y_enc, BIT_LENGTH, scheme_paillier)
    z, beta = bob.step_2(z_enc, BIT_LENGTH, scheme_paillier)
    alpha = alice.step_3(r, BIT_LENGTH)
    d_enc_2 = bob.step_4a(z, scheme_dgk_not_full, scheme_paillier, BIT_LENGTH)
    beta_is_enc = bob.step_4b(beta, BIT_LENGTH, scheme_dgk_not_full)
    d_enc = alice.step_4c(d_enc_2, r, scheme_dgk_not_full, scheme_paillier)
    alpha_is_xor_beta_is_enc = alice.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = alice.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme_paillier
    )
    w_is_enc = alice.step_4f(w_is_enc)
    s, delta_a = alice.step_4g()
    c_is_enc = alice.step_4h(
        s,
        alpha,
        alpha_tilde,
        d_enc,
        beta_is_enc,
        w_is_enc,
        delta_a,
        scheme_dgk_not_full,
    )
    c_is_enc = alice.step_4i(c_is_enc, scheme_dgk_not_full)
    delta_b = bob.step_4j(c_is_enc, scheme_dgk_not_full)
    zeta_1_enc, zeta_2_enc, delta_b_enc = bob.step_5(
        z, BIT_LENGTH, delta_b, scheme_paillier
    )
    beta_lt_alpha_enc = alice.step_6(delta_a, delta_b_enc)
    x_leq_y_enc = alice.step_7(
        zeta_1_enc, zeta_2_enc, r, BIT_LENGTH, beta_lt_alpha_enc, scheme_paillier
    )
    return x_leq_y_enc


async def run_interactive_comparison(
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
) -> PaillierCiphertext:
    """
    Perform integral comparison protocol including communication
    between Initiator and KeyHolder for integration test.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input.
    :return: Encryption of x <= y.
    """
    initiator = Initiator(
        BIT_LENGTH,
        communicator=communicator_alice,
        scheme_paillier=scheme_paillier,
        scheme_dgk=scheme_dgk_not_full,
    )
    keyholder = KeyHolder(
        BIT_LENGTH,
        communicator=communicator_bob,
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
    "number", test_vals_smaller_plaintext + test_vals_bigger_plaintext
)
def test_bit_conversion(number: int) -> None:
    """
    Assert that conversion of a integer to bits and back returns the
    initial integer.

    :param number: Number to be converted.
    """
    assert from_bits(to_bits(number, BIT_LENGTH))


@pytest.mark.parametrize(
    "x, y, x_enc, y_enc",
    list(
        zip(
            test_vals_smaller_plaintext,
            test_vals_bigger_plaintext,
            test_vals_smaller,
            test_vals_bigger,
        )
    ),
)
def test_step_1(
    x: int, y: int, x_enc: PaillierCiphertext, y_enc: PaillierCiphertext
) -> None:
    r"""
    Assert that the computation in 'step_1' is equal to the alternative method
    of computation the authors give. In 'step_1', $[[z]] =
    [[y]] \cdot [[x]]^{-1} \cdot [[2^l + r]] = [[y]] - [[x]] + [[2^l + r]]$ is computed.
    Here, we compute $[[z]] \leftarrow [[y - x + 2^l + r]] \text{ mod } N^2$ and check
    whether it matches the approach above.

    :param x: First input as plaintext.
    :param y: Second input as plaintext.
    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    l = BIT_LENGTH
    z_enc, r = alice.step_1(x_enc, y_enc, l, scheme_paillier)
    z_enc_test = scheme_paillier.unsafe_encrypt(
        (y - x + (1 << l) + r) % scheme_paillier.public_key.n_squared,
        apply_encoding=False,
    )
    assert scheme_paillier.decrypt(z_enc_test) == scheme_paillier.decrypt(z_enc)


@pytest.mark.parametrize("x, y, x_enc, y_enc, l, boolean_result", test_constraints_l)
def test_step_1_constraints_l(
    x: int,
    y: int,
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
    l: int,
    boolean_result: bool,
) -> None:
    r"""
    Assert that the constraint on $l$ are checked in the function alice.step_1.
    The constraint, as stated in Protocol 3, is $l + 2 < log_2(N)$.

    :param x: First input as plaintext.
    :param y: Second input as plaintext.
    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    :param l: Bit length.
    :param boolean_result: Boolean result of whether the value of l should
        raise an error in the function under test.
    """
    if boolean_result:
        with pytest.raises(AssertionError):
            alice.step_1(x_enc, y_enc, l, scheme_paillier)
    else:
        z_enc, r = alice.step_1(x_enc, y_enc, l, scheme_paillier)
        z_enc_test = scheme_paillier.unsafe_encrypt(
            (y - x + (1 << l) + r) % scheme_paillier.public_key.n_squared,
            apply_encoding=False,
        )
        assert scheme_paillier.decrypt(z_enc_test) == scheme_paillier.decrypt(z_enc)


def test_modulo_n_squared() -> None:
    r"""
    Assert that the modulo reduction by $N^2$ is performed. It is not explicitly done
    in the code under test, but it is handled by the Paillier encryption.
    Note that the value of $y$ does not adhere to $0 \leq y < 2^l$. We chose the
    values of $x$ and $y$ such that z_enc needs modulo reduction.
    """
    l = BIT_LENGTH
    x = 0
    x_enc = scheme_paillier.unsafe_encrypt(x, apply_encoding=False)
    y_enc = PaillierCiphertext(
        scheme_paillier.public_key.n_squared - 2, scheme_paillier
    )
    y = int(scheme_paillier.decrypt(y_enc, apply_encoding=False))
    r = scheme_paillier.public_key.n_squared

    z_enc = (
        y_enc
        - x_enc
        + scheme_paillier.unsafe_encrypt((1 << l) + r, apply_encoding=False)
    )
    z = (y - x + (1 << l) + r) % scheme_paillier.public_key.n_squared
    assert z == int(scheme_paillier.decrypt(z_enc, apply_encoding=False))


@pytest.mark.parametrize(
    "x_enc, y_enc",
    list(
        zip(
            test_vals_smaller,
            test_vals_bigger,
        )
    ),
)
def test_step_2(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    Assert that the modulo reduction is performed correctly. We do this basically by checking
    whether $2^l$ is the same as $(1 << l)$.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    l = BIT_LENGTH
    z_enc, _r = alice.step_1(x_enc, y_enc, l, scheme_paillier)
    z = int(scheme_paillier.decrypt(z_enc, apply_encoding=False))
    beta = z % 2**l
    z_test, beta_test = bob.step_2(z_enc, l, scheme_paillier)
    assert z_test == z and beta_test == beta


@pytest.mark.parametrize("z", test_4a)
def test_step_4a(z: int) -> None:
    r"""
    Assert that $d$ is computed based on the value of $z$
    and is encrypted.

    :param z: Plaintext result of step 1, here hand-picked.
    """

    d = bool(z < (paillier_n - 1) // 2)

    d_enc = bob.step_4a(z, scheme_dgk_full, scheme_paillier, BIT_LENGTH)
    assert d == scheme_dgk_full.decrypt(d_enc)


@pytest.mark.parametrize(
    "x_enc, y_enc",
    list(
        zip(
            test_vals_smaller,
            test_vals_bigger,
        )
    ),
)
def test_step_4b(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    Assert that $\beta$ is transformed correctly into bits and the bitwise
    encryption is correct.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    z_enc, _r = alice.step_1(x_enc, y_enc, BIT_LENGTH, scheme_paillier)
    _z, beta = bob.step_2(z_enc, BIT_LENGTH, scheme_paillier)
    beta_bin_raw = bin(beta)[2:]
    beta_bin = [int(bit) for bit in beta_bin_raw]
    beta_bin.reverse()
    while len(beta_bin) != BIT_LENGTH:
        beta_bin.append(0)

    beta_is_enc = bob.step_4b(beta, BIT_LENGTH, scheme_dgk_full)
    for index, bit in enumerate(beta_is_enc):
        assert scheme_dgk_full.decrypt(bit) == int(beta_bin[index])


@pytest.mark.parametrize("d_enc, r, test_result, assertion", test_4c)
def test_step_4c(
    d_enc: DGKCiphertext, r: int, test_result: DGKCiphertext, assertion: bool
) -> None:
    r"""
    The value of $[d]$ is corrected based on the value of $r$. 'step_4c'
    should give an assertion error if the constraint $0 \leq r < (N-1) \div 2$
    is not met.

    :param d_enc: Encrypted bit.
    :param r: The randomness value $r$ from step 1. Here the value is hand-picked.
    :param test_result: The expected output of 'step_4c', $[d]$.
    :param assertion: Boolean value stating whether the program should assert
        based on the constraints.
    """
    if assertion:
        with pytest.raises(AssertionError):
            alice.step_4c(d_enc, r, scheme_dgk_full, scheme_paillier)
    else:
        d_enc_corrected = alice.step_4c(d_enc, r, scheme_dgk_full, scheme_paillier)
        assert scheme_dgk_full.decrypt(d_enc_corrected) == test_result


@pytest.mark.parametrize("alpha, beta", test_4d)
def test_step_4d(alpha: List[int], beta: List[int]) -> None:
    r"""
    Assert that $[\alpha_i \oplus \beta_i]$ is computed correctly.
    Here we compute the value using the unencrypted values and check
    whether the decryption of the encrypted output of 'step_4d' is the same.

    :param alpha: Computed value in 'step_3' by A, here hand-picked.
    :param beta: Computed value in 'step_2' by B, here hand-picked.
    """
    beta_is_enc = [
        scheme_dgk_full.unsafe_encrypt(beta[i], apply_encoding=False)
        for i in range(BIT_LENGTH)
    ]
    for i in range(BIT_LENGTH):
        alpha_xor_beta = alpha[i] ^ beta[i]
        alpha_is_xor_beta_is_enc = alice.step_4d(alpha, beta_is_enc)
        assert alpha_xor_beta == scheme_dgk_full.decrypt(alpha_is_xor_beta_is_enc[i])


@pytest.mark.parametrize("x_enc, y_enc", list(zip(test_vals_smaller, test_vals_bigger)))
def test_step_4e(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    Assert that the value of $[w_i]$ is set correctly. We compute this slightly
    different than in 'step_4e', namely we make use of the multiplicative inverse and
    homomorphism to reduce the equation in a different manner.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    z_enc, r = alice.step_1(x_enc, y_enc, BIT_LENGTH, scheme_paillier)
    z, beta = bob.step_2(z_enc, BIT_LENGTH, scheme_paillier)
    alpha = alice.step_3(r, BIT_LENGTH)
    d_enc = bob.step_4a(z, scheme_dgk_full, scheme_paillier, BIT_LENGTH)
    beta_is_enc = bob.step_4b(beta, BIT_LENGTH, scheme_dgk_full)
    d_enc = alice.step_4c(d_enc, r, scheme_dgk_full, scheme_paillier)
    alpha_is_xor_beta_is_enc = alice.step_4d(alpha, beta_is_enc)
    w_is_enc, _alpha_tilde = alice.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme_paillier
    )
    alpha_tilde_test = (r - paillier_n) % (1 << BIT_LENGTH)
    alpha_tilde_test_bits = to_bits(alpha_tilde_test, BIT_LENGTH)
    beta_bits = to_bits(beta, BIT_LENGTH)
    d = int(scheme_dgk_full.decrypt(d_enc))

    for i in range(BIT_LENGTH):
        if alpha[i] == alpha_tilde_test_bits[i]:
            assert scheme_dgk_full.decrypt(w_is_enc[i]) == alpha[i] ^ beta_bits[i]
        else:
            assert scheme_dgk_full.decrypt(w_is_enc[i]) == alpha[i] ^ beta_bits[i] - d


@pytest.mark.parametrize("x_enc, y_enc", list(zip(test_vals_smaller, test_vals_bigger)))
def test_step_4f(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    We basically test whether multiplication by a bit $i$ that is left-shifted
    every iteration is the same as multiplcation by $2^i$. We can't check whether
    $[w_i]^{2^i}$ works, as exponentation of PaillierCiphertexts is not implemented.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    z_enc, r = alice.step_1(x_enc, y_enc, BIT_LENGTH, scheme_paillier)
    z, beta = bob.step_2(z_enc, BIT_LENGTH, scheme_paillier)
    alpha = alice.step_3(r, BIT_LENGTH)
    d_enc = bob.step_4a(z, scheme_dgk_full, scheme_paillier, BIT_LENGTH)
    beta_is_enc = bob.step_4b(beta, BIT_LENGTH, scheme_dgk_full)
    d_enc = alice.step_4c(d_enc, r, scheme_dgk_full, scheme_paillier)
    alpha_is_xor_beta_is_enc = alice.step_4d(alpha, beta_is_enc)
    w_is_enc, _alpha_tilde = alice.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme_paillier
    )
    w_test = [
        int(scheme_dgk_full.decrypt(w_is_enc[i]))
        * (2**i)
        % scheme_dgk_full.public_key.u
        for i in range(BIT_LENGTH)
    ]
    w_is_enc = alice.step_4f(w_is_enc)
    for i in range(BIT_LENGTH):
        assert w_test[i] == int(
            scheme_dgk_full.decrypt(w_is_enc[i], apply_encoding=False)
        )


@pytest.mark.parametrize("x_enc, y_enc", list(zip(test_vals_smaller, test_vals_bigger)))
def test_step_4h(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    Assert that the value of $[c_i]$ is computed correctly. We do this by calculating
    it slightly different, namely $[c_i] = s + \alpha_i
    d*(\tilde{\alpha}_i-\alpha_i) - \beta_i] + 3*(\Sigma^{l-1}_{j=i+1}[w_j]) \mod n$
    instead of $[c_i] = [s] \cdot [\alpha_i] \cdot
    [d]^{\tilde{\alpha}_i-\alpha_i} \cdot [\beta_i]^{-1} \cdot (\Pi^{l-1}_{j=i+1}[w_j])^3 \mod n$.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    z_enc, r = alice.step_1(x_enc, y_enc, BIT_LENGTH, scheme_paillier)
    z, beta = bob.step_2(z_enc, BIT_LENGTH, scheme_paillier)
    alpha = alice.step_3(r, BIT_LENGTH)
    d_enc = bob.step_4a(z, scheme_dgk_full, scheme_paillier, BIT_LENGTH)
    beta_is_enc = bob.step_4b(beta, BIT_LENGTH, scheme_dgk_full)
    d_enc = alice.step_4c(d_enc, r, scheme_dgk_full, scheme_paillier)
    alpha_is_xor_beta_is_enc = alice.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = alice.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme_paillier
    )
    w_is_enc = alice.step_4f(w_is_enc)
    s, delta_a = alice.step_4g()
    c_is_enc = alice.step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, scheme_dgk_full
    )
    d = int(scheme_dgk_full.decrypt(d_enc))
    beta_bits = to_bits(beta, BIT_LENGTH)

    for i in range(BIT_LENGTH):
        temp = int(
            s
            + alpha[i]
            + (alpha_tilde[i] - alpha[i]) * d
            - beta_bits[i]
            + 3 * sum([int(scheme_dgk_full.decrypt(wj)) for wj in w_is_enc[i + 1 :]])
        )
        assert (
            temp % scheme_dgk_full.public_key.u
            == int(scheme_dgk_full.decrypt(c_is_enc[i + 1]))
            % scheme_dgk_full.public_key.u
        )


@pytest.mark.parametrize("x_enc, y_enc", list(zip(test_vals_smaller, test_vals_bigger)))
def test_step_4j(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    Assert that $\delta_B$ is set correctly. If any of the values in $c_i$
    decrypts to 0, $\delta_B$ should be 1. We check this by iterating over $[c_i]$
    for all $0 \leq i < l$ and checking the result with the result of 'step_4i'.
    However, the resulting list of that step is one element too long: there is an
    element prepended, which we leave out of consideration here.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    z_enc, r = alice.step_1(x_enc, y_enc, BIT_LENGTH, scheme_paillier)
    z, beta = bob.step_2(z_enc, BIT_LENGTH, scheme_paillier)
    alpha = alice.step_3(r, BIT_LENGTH)
    d_enc = bob.step_4a(z, scheme_dgk_full, scheme_paillier, BIT_LENGTH)
    beta_is_enc = bob.step_4b(beta, BIT_LENGTH, scheme_dgk_full)
    d_enc = alice.step_4c(d_enc, r, scheme_dgk_full, scheme_paillier)
    alpha_is_xor_beta_is_enc = alice.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = alice.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme_paillier
    )
    w_is_enc = alice.step_4f(w_is_enc)
    s, delta_a = alice.step_4g()
    c_is_enc = alice.step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, scheme_dgk_full
    )
    c_is_enc = alice.step_4i(c_is_enc, scheme_dgk_full)
    delta_b = bob.step_4j(c_is_enc, scheme_dgk_full)

    for i in range(BIT_LENGTH):
        if scheme_dgk_full.is_zero(
            c_is_enc[i + 1]
        ):  # Plus 1 here to correct the element added in alice.step_4h
            assert delta_b == 1


@pytest.mark.parametrize("z, delta_b", test_5)
def test_step_5(z: int, delta_b: int) -> None:
    r"""
    We compute $z \div 2^l$ slightly different than in 'step_5'. Namely
    we have eliminated the if-statement and have used a masking technique.

    :param z: Result of 'step_1', here hand-picked.
    :param delta_b: Bit result of 'step_4j'. Here the value is hand-picked.
    """
    l = BIT_LENGTH
    n = scheme_paillier.public_key.n
    zeta_1_enc, zeta_2_enc, delta_b_enc = bob.step_5(
        z, BIT_LENGTH, delta_b, scheme_paillier
    )
    assert scheme_paillier.decrypt(zeta_1_enc) == z // (2**l)
    assert scheme_paillier.decrypt(zeta_2_enc) == int(z < (n - 1) // 2) * (
        (z + n) // (2**l)
    ) + int(z >= (n - 1) // 2) * (z // (2**l))
    assert scheme_paillier.decrypt(delta_b_enc) == delta_b


@pytest.mark.parametrize("delta_a, delta_b_enc", test_6)
def test_step_6(delta_a: int, delta_b_enc: PaillierCiphertext) -> None:
    r"""
    Test whether $[[\beta < \alpha]]$ is computed correctly. We
    have eliminated the if-statement and have used a masking technique.
    We also used the value of $\delta_B$ directly, instead of using the
    encrypted value as should be used in the protocol.

    :param delta_a: Bit value computed in 'step_4g', here this is hand-picked.
    :param delta_b_enc: Encrypted bit computed in 'step_5', here this is hand-picked.
    """
    beta_lt_alpha_enc = alice.step_6(delta_a, delta_b_enc)
    delta_a_true_part = delta_a * delta_b_enc
    delta_a_false_part = int(not delta_a) * (1 - scheme_paillier.decrypt(delta_b_enc))
    assert scheme_paillier.decrypt(beta_lt_alpha_enc) == scheme_paillier.decrypt(
        delta_a_true_part + delta_a_false_part
    )


@pytest.mark.parametrize("x_enc, y_enc", list(zip(test_vals_smaller, test_vals_bigger)))
def test_step_7(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    Assert that the computation of $x \leq y$ is correct. In the function 'step_7'
    the multiplicative inverse is used to negate an encrypted integer: $[-x] = [x]^{-1}$.
    This comes in handy, as we cannot compute the multiplication of two PaillierCiphertexts.
    However, here we can just work with the unencrypted values, such that we can multiply
    them.
    (Note: the fix mentioned in 'step_7' about $\zeta_1$ and $\zeta_2$ is not used here)

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    z_enc, r = alice.step_1(x_enc, y_enc, BIT_LENGTH, scheme_paillier)
    z, beta = bob.step_2(z_enc, BIT_LENGTH, scheme_paillier)
    alpha = alice.step_3(r, BIT_LENGTH)
    d_enc = bob.step_4a(z, scheme_dgk_full, scheme_paillier, BIT_LENGTH)
    beta_is_enc = bob.step_4b(beta, BIT_LENGTH, scheme_dgk_full)
    d_enc = alice.step_4c(d_enc, r, scheme_dgk_full, scheme_paillier)
    alpha_is_xor_beta_is_enc = alice.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = alice.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme_paillier
    )
    w_is_enc = alice.step_4f(w_is_enc)
    s, delta_a = alice.step_4g()
    c_is_enc = alice.step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, scheme_dgk_full
    )
    c_is_enc = alice.step_4i(c_is_enc, scheme_dgk_full)
    delta_b = bob.step_4j(c_is_enc, scheme_dgk_full)
    zeta_1_enc, zeta_2_enc, delta_b_enc = bob.step_5(
        z, BIT_LENGTH, delta_b, scheme_paillier
    )
    beta_lt_alpha_enc = alice.step_6(delta_a, delta_b_enc)
    x_leq_y_enc = alice.step_7(
        zeta_1_enc, zeta_2_enc, r, BIT_LENGTH, beta_lt_alpha_enc, scheme_paillier
    )
    x_leq_y = (z // (2**BIT_LENGTH)) - (
        (r // (2**BIT_LENGTH)) + (int(beta < from_bits(alpha)))
    ) % scheme_paillier.public_key.n_squared

    assert x_leq_y == scheme_paillier.decrypt(x_leq_y_enc)


@pytest.mark.parametrize("x_enc, y_enc", list(zip(test_vals_smaller, test_vals_bigger)))
@pytest.mark.asyncio
async def test_smaller_than(
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
) -> None:
    """
    Assert that the secure comparison returns the expected result when the
    input satisfies a "smaller than" relation, interactive and non-interactive.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    x_leq_y_enc = run_comparison(x_enc, y_enc)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert x_leq_y == 1

    x_leq_y_enc = await run_interactive_comparison(x_enc, y_enc)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert x_leq_y == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("x_enc, y_enc", list(zip(test_vals_bigger, test_vals_smaller)))
async def test_greater_than(
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
) -> None:
    """
    Assert that the secure comparison returns the expected result when the
    input satisfies a "greater than" relation, interactive and non-interactive.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc > y_enc.
    """
    x_leq_y_enc = run_comparison(x_enc, y_enc)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert x_leq_y == 0

    x_leq_y_enc = await run_interactive_comparison(x_enc, y_enc)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert x_leq_y == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("x_enc, y_enc", list(zip(test_vals_bigger, test_vals_bigger)))
async def test_equal_to(
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
) -> None:
    """
    Assert that the secure comparison returns the expected result when the
    input satisfies a "is equal to" relation, interactive and non-interactive.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc == y_enc.
    """
    x_leq_y_enc = run_comparison(x_enc, y_enc)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert x_leq_y == 1

    x_leq_y_enc = await run_interactive_comparison(x_enc, y_enc)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert x_leq_y == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("x_enc, y_enc, boolean_result", test_conversion_to_bool)
async def test_conversion_to_boolean(
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
    boolean_result: bool,
) -> None:
    """
    Test conversion from decrypted result to boolean. If this test fails,
    the issue is probably in a depencency; however, the users of this package
    expect that the decrypted result works properly as a boolean and so we
    should know. Tests for interactive and non-interactive.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input.
    :param boolean_result: Boolean result of the comparison on the plaintext
        values of x_enc and y_enc, e.g. (x <= y).
    """
    x_leq_y_enc = run_comparison(x_enc, y_enc)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert bool(x_leq_y) == boolean_result

    x_leq_y_enc = await run_interactive_comparison(x_enc, y_enc)
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert bool(x_leq_y) == boolean_result


@pytest.mark.asyncio
async def test_initiator_no_secret_key() -> None:
    """
    Test that checks that if the initiator receives the encryption schemes from
    the key holder, that they don't contain the secret key.
    """

    initiator = Initiator(
        BIT_LENGTH,
        communicator=communicator_alice,
    )
    keyholder = KeyHolder(
        BIT_LENGTH,
        communicator=communicator_bob,
        scheme_paillier=scheme_paillier,
        scheme_dgk=scheme_dgk_full,
    )

    task_send_keys = asyncio.create_task(keyholder.make_and_send_encryption_schemes())
    task_receive_keys = asyncio.create_task(initiator.receive_encryption_schemes())

    await asyncio.gather(*[task_send_keys, task_receive_keys])

    initiator.scheme_paillier = cast(Paillier, initiator.scheme_paillier)
    initiator.scheme_dgk = cast(DGK, initiator.scheme_dgk)

    assert (
        initiator.scheme_paillier.secret_key == None == initiator.scheme_dgk.secret_key
    )


@pytest.mark.asyncio
async def test_parallel_runs() -> None:
    """
    Test multiple runs of `perform_secure_comparison simultaneously.
    """
    initiator = Initiator(
        BIT_LENGTH,
        communicator=communicator_alice,
    )
    keyholder = KeyHolder(
        BIT_LENGTH,
        communicator=communicator_bob,
        scheme_paillier=scheme_paillier,
        scheme_dgk=scheme_dgk_not_full,
    )

    x_enc_1 = scheme_paillier.unsafe_encrypt(11)
    x_enc_2 = scheme_paillier.unsafe_encrypt(41)
    y_enc_1 = scheme_paillier.unsafe_encrypt(12)
    y_enc_2 = scheme_paillier.unsafe_encrypt(41)

    task_alice_1 = asyncio.create_task(
        initiator.perform_secure_comparison(x_enc_1, y_enc_1)
    )
    task_alice_2 = asyncio.create_task(
        initiator.perform_secure_comparison(x_enc_2, y_enc_2)
    )
    task_bob_1 = asyncio.create_task(keyholder.perform_secure_comparison())
    task_bob_2 = asyncio.create_task(keyholder.perform_secure_comparison())

    x_leq_y_1, _, x_leq_y_2, _ = await asyncio.gather(
        *(task_alice_1, task_bob_1, task_alice_2, task_bob_2)
    )

    assert scheme_paillier.decrypt(x_leq_y_1) == 1 == scheme_paillier.decrypt(x_leq_y_2)
