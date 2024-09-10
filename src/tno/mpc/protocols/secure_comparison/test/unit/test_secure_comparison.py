"""
Unit tests for the tno.mpc.protocols.secure_comparison library.
"""

from __future__ import annotations

import asyncio

import pytest

from tno.mpc.encryption_schemes.dgk import DGK, DGKCiphertext
from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
from tno.mpc.encryption_schemes.utils import next_prime

from tno.mpc.protocols.secure_comparison import Initiator, KeyHolder, from_bits, to_bits
from tno.mpc.protocols.secure_comparison.test.conftest import COMPARISON_BIT_LENGTH

# Setting up the encryption schemes.
paillier = Paillier.from_security_parameter(key_length=1024)
paillier_n = paillier.public_key.n

# Sometimes we want full decryption to make checks.
u = next_prime(1 << (COMPARISON_BIT_LENGTH + 2))
dgk_full = DGK.from_security_parameter(v_bits=20, n_bits=128, u=u, full_decryption=True)

# Pairs (x, y) where x < y
_TEST_VALUES_SMALL_BIG = [
    (-400, -383),
    (-1, 0),
    (0, 2),
    (1, 10),
    (230, 269),
    (1508, 2408),
    (3122, 6048),
    (4250, 7804),
    (8668, 9015),
]
TEST_VALS_SMALLER_PLAINTEXT, TEST_VALS_BIGGER_PLAINTEXT = tuple(
    zip(*_TEST_VALUES_SMALL_BIG)
)
TEST_VALS_SMALLER = list(map(paillier.unsafe_encrypt, TEST_VALS_SMALLER_PLAINTEXT))
TEST_VALS_BIGGER = list(map(paillier.unsafe_encrypt, TEST_VALS_BIGGER_PLAINTEXT))
TEST_CONVERSION_TO_BOOL = [
    (TEST_VALS_SMALLER_PLAINTEXT[0], TEST_VALS_BIGGER_PLAINTEXT[0], True),
    (TEST_VALS_BIGGER_PLAINTEXT[0], TEST_VALS_SMALLER_PLAINTEXT[0], False),
    (TEST_VALS_BIGGER_PLAINTEXT[0], TEST_VALS_BIGGER_PLAINTEXT[0], True),
]
TEST_4A = [
    (0),
    (paillier_n),
    ((paillier_n - 1) // 2),
]
TEST_4D = [
    (to_bits(12345, COMPARISON_BIT_LENGTH), to_bits(23456, COMPARISON_BIT_LENGTH)),
    (to_bits(25, COMPARISON_BIT_LENGTH), to_bits(890, COMPARISON_BIT_LENGTH)),
]
TEST_5 = [
    (paillier.public_key.n, 0),
    (100, 0),
    (paillier.public_key.n, 1),
    (100, 1),
]
TEST_6 = [
    (0, paillier.unsafe_encrypt(0, apply_encoding=False)),
    (0, paillier.unsafe_encrypt(1, apply_encoding=False)),
    (1, paillier.unsafe_encrypt(0, apply_encoding=False)),
    (1, paillier.unsafe_encrypt(1, apply_encoding=False)),
]


def run_comparison(
    x_enc: PaillierCiphertext,
    y_enc: PaillierCiphertext,
    paillier_scheme: Paillier,
    dgk_scheme_not_full: DGK,
) -> PaillierCiphertext:
    """
    Perform integral comparison protocol for integration test.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input.
    :param paillier_scheme: Paillier scheme.
    :param dgk_scheme_not_full: DGK scheme.
    :return: Encryption of x <= y.
    """
    z_enc, r = Initiator.step_1(x_enc, y_enc, COMPARISON_BIT_LENGTH, paillier_scheme)
    z, beta = KeyHolder.step_2(z_enc, COMPARISON_BIT_LENGTH, paillier_scheme)
    alpha = Initiator.step_3(r, COMPARISON_BIT_LENGTH)
    d_enc_2 = KeyHolder.step_4a(
        z, dgk_scheme_not_full, paillier_scheme, COMPARISON_BIT_LENGTH
    )
    beta_is_enc = KeyHolder.step_4b(beta, COMPARISON_BIT_LENGTH, dgk_scheme_not_full)
    d_enc = Initiator.step_4c(d_enc_2, r, dgk_scheme_not_full, paillier_scheme)
    alpha_is_xor_beta_is_enc = Initiator.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = Initiator.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, paillier_scheme
    )
    w_is_enc = Initiator.step_4f(w_is_enc)
    s, delta_a = Initiator.step_4g()
    c_is_enc = Initiator.step_4h(
        s,
        alpha,
        alpha_tilde,
        d_enc,
        beta_is_enc,
        w_is_enc,
        delta_a,
        dgk_scheme_not_full,
    )
    c_is_enc = Initiator.step_4i(c_is_enc, dgk_scheme_not_full)
    delta_b = KeyHolder.step_4j(c_is_enc, dgk_scheme_not_full)
    zeta_1_enc, zeta_2_enc, delta_b_enc = KeyHolder.step_5(
        z, COMPARISON_BIT_LENGTH, delta_b, paillier_scheme
    )
    beta_lt_alpha_enc = Initiator.step_6(delta_a, delta_b_enc)
    x_leq_y_enc = Initiator.step_7(
        zeta_1_enc,
        zeta_2_enc,
        r,
        COMPARISON_BIT_LENGTH,
        beta_lt_alpha_enc,
        paillier_scheme,
    )
    return x_leq_y_enc


async def run_interactive_comparison(
    x: PaillierCiphertext | float,
    y: PaillierCiphertext | float,
    alice: Initiator,
    bob: KeyHolder,
) -> PaillierCiphertext:
    """
    Perform integral comparison protocol including communication
    between Initiator and KeyHolder for integration test.

    :param x: (Encryption of) first input.
    :param y: (Encryption of) second input.
    :param alice: Initiator of the secure comparison.
    :param bob: Keyholder in the secure comparison.
    :return: Encryption of x <= y.
    """
    task_initiator = asyncio.create_task(alice.perform_secure_comparison(x, y))
    task_keyholder = asyncio.create_task(bob.perform_secure_comparison())

    x_leq_y_enc, _ = await asyncio.gather(*(task_initiator, task_keyholder))
    return x_leq_y_enc


@pytest.mark.parametrize(
    "number",
    filter(
        lambda val: val >= 0, TEST_VALS_SMALLER_PLAINTEXT + TEST_VALS_BIGGER_PLAINTEXT  # type: ignore[operator, arg-type]
    ),
)
def test_bit_conversion(number: int) -> None:
    """
    Assert that conversion of a non-negative integer to bits and back
    returns the initial integer.

    :param number: Number to be converted.
    """
    assert from_bits(to_bits(number, COMPARISON_BIT_LENGTH)) == number


def test_modulo_n_squared() -> None:
    r"""
    Assert that the modulo reduction by $N^2$ is performed. It is not explicitly done
    in the code under test, but it is handled by the Paillier encryption.
    Note that the value of $y$ does not adhere to $0 \leq y < 2^l$. We chose the
    values of $x$ and $y$ such that z_enc needs modulo reduction.
    """
    l = COMPARISON_BIT_LENGTH
    x = 0
    x_enc = paillier.unsafe_encrypt(x, apply_encoding=False)
    y_enc = PaillierCiphertext(paillier.public_key.n_squared - 2, paillier)
    y = int(paillier.decrypt(y_enc, apply_encoding=False))
    r = paillier.public_key.n_squared

    z_enc = y_enc - x_enc + paillier.unsafe_encrypt((1 << l) + r, apply_encoding=False)
    z = (y - x + (1 << l) + r) % paillier.public_key.n_squared
    assert z == int(paillier.decrypt(z_enc, apply_encoding=False))


@pytest.mark.parametrize(
    "x, y, x_enc, y_enc",
    list(
        zip(
            TEST_VALS_SMALLER_PLAINTEXT,
            TEST_VALS_BIGGER_PLAINTEXT,
            TEST_VALS_SMALLER,
            TEST_VALS_BIGGER,
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
    l = COMPARISON_BIT_LENGTH
    z_enc, r = Initiator.step_1(x_enc, y_enc, l, paillier)
    z_enc_test = paillier.unsafe_encrypt(
        (y - x + (1 << l) + r) % paillier.public_key.n_squared,
        apply_encoding=False,
    )
    assert paillier.decrypt(z_enc_test) == paillier.decrypt(z_enc)


def test_step_1_constraints_l_accepted_when_met() -> None:
    r"""
    Assert that valid constraints on $l$ are accepted by the function
    Initiator.step_1. The constraint, as stated in Protocol 3, is
    $l + 2 < log_2(N)$.
    """
    x = 1
    y = 2
    x_enc = paillier.unsafe_encrypt(x)
    y_enc = paillier.unsafe_encrypt(y)
    l = COMPARISON_BIT_LENGTH

    z_enc, r = Initiator.step_1(x_enc, y_enc, l, paillier)
    z_enc_test = paillier.unsafe_encrypt(
        (y - x + (1 << l) + r) % paillier.public_key.n_squared,
        apply_encoding=False,
    )
    assert paillier.decrypt(z_enc_test) == paillier.decrypt(z_enc)


def test_step_1_constraints_l_rejected_when_not_met() -> None:
    r"""
    Assert that invalid constraints on $l$ are rejected by the function
    Initiator.step_1. The constraint, as stated in Protocol 3, is
    $l + 2 < log_2(N)$.
    """
    l = paillier.public_key.n.bit_length() - 2
    x_enc = paillier.unsafe_encrypt(1)
    y_enc = paillier.unsafe_encrypt(2)

    with pytest.raises(AssertionError):
        Initiator.step_1(x_enc, y_enc, l, paillier)


@pytest.mark.parametrize(
    "x_enc, y_enc",
    list(
        zip(
            TEST_VALS_SMALLER,
            TEST_VALS_BIGGER,
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
    l = COMPARISON_BIT_LENGTH
    z_enc, _r = Initiator.step_1(x_enc, y_enc, l, paillier)
    z = int(paillier.decrypt(z_enc, apply_encoding=False))
    beta = z % 2**l
    z_test, beta_test = KeyHolder.step_2(z_enc, l, paillier)
    assert z_test == z and beta_test == beta


@pytest.mark.parametrize("z", TEST_4A)
def test_step_4a(z: int) -> None:
    r"""
    Assert that $d$ is computed based on the value of $z$
    and is encrypted.

    :param z: Plaintext result of step 1, here hand-picked.
    """

    d = bool(z < (paillier_n - 1) // 2)

    d_enc = KeyHolder.step_4a(z, dgk_full, paillier, COMPARISON_BIT_LENGTH)
    assert d == dgk_full.decrypt(d_enc)


@pytest.mark.parametrize(
    "x_enc, y_enc",
    list(
        zip(
            TEST_VALS_SMALLER,
            TEST_VALS_BIGGER,
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
    z_enc, _ = Initiator.step_1(x_enc, y_enc, COMPARISON_BIT_LENGTH, paillier)
    _, beta = KeyHolder.step_2(z_enc, COMPARISON_BIT_LENGTH, paillier)
    beta_bin_raw = bin(beta)[2:]
    beta_bin = [int(bit) for bit in beta_bin_raw]
    beta_bin.reverse()
    while len(beta_bin) != COMPARISON_BIT_LENGTH:
        beta_bin.append(0)

    beta_is_enc = KeyHolder.step_4b(beta, COMPARISON_BIT_LENGTH, dgk_full)
    for index, bit in enumerate(beta_is_enc):
        assert dgk_full.decrypt(bit) == int(beta_bin[index])


@pytest.mark.parametrize(
    "d_enc, r",
    [
        (dgk_full.unsafe_encrypt(0, apply_encoding=False), 0),
        (dgk_full.unsafe_encrypt(1, apply_encoding=False), 0),
        (dgk_full.unsafe_encrypt(0, apply_encoding=False), 100),
        (dgk_full.unsafe_encrypt(1, apply_encoding=False), 100),
    ],
)
def test_step_4c_sets_to_zero(
    d_enc: DGKCiphertext,
    r: int,
) -> None:
    r"""
    The value of $[d]$ is set to zero if $r$ is smaller than half the paillier
    scheme modulus.

    :param d_enc: Encrypted bit.
    :param r: The randomness value $r$ from step 1. Here the value is
        hand-picked.
    """
    d_enc_corrected = Initiator.step_4c(d_enc, r, dgk_full, paillier)
    assert dgk_full.decrypt(d_enc_corrected) == 0


@pytest.mark.parametrize(
    "d_enc, r, test_result",
    [
        (dgk_full.unsafe_encrypt(0, apply_encoding=False), paillier_n - 100, 0),
        (dgk_full.unsafe_encrypt(1, apply_encoding=False), paillier_n - 100, 1),
    ],
)
def test_step_4c_maintains_original_value(
    d_enc: DGKCiphertext,
    r: int,
    test_result: int,
) -> None:
    r"""
    The value of $[d]$ maintains its value if $r$ is at least half the
        paillier scheme modulus.

    :param d_enc: Encrypted bit.
    :param r: The randomness value $r$ from step 1. Here the value is
        hand-picked.
    :param test_result: The expected output of 'step_4c', $[d]$.
    """
    d_enc_corrected = Initiator.step_4c(d_enc, r, dgk_full, paillier)
    assert dgk_full.decrypt(d_enc_corrected) == test_result


@pytest.mark.parametrize("r", [-10, paillier_n + 10])
def test_step_4c_raises_valueerror_for_inappropriate_randomness(r: int) -> None:
    r"""
    The value of $[d]$ is corrected based on the value of $r$. 'step_4c'
    should give an assertion error if the constraint $0 \leq r < (N-1) \div 2$
    is not met.

    :param r: The provided, incorrect, randomness.
    """
    d_enc = dgk_full.unsafe_encrypt(0, apply_encoding=False)

    with pytest.raises(AssertionError):
        Initiator.step_4c(d_enc, r, dgk_full, paillier)


@pytest.mark.parametrize("alpha, beta", TEST_4D)
def test_step_4d(alpha: list[int], beta: list[int]) -> None:
    r"""
    Assert that $[\alpha_i \oplus \beta_i]$ is computed correctly.
    Here we compute the value using the unencrypted values and check
    whether the decryption of the encrypted output of 'step_4d' is the same.

    :param alpha: Computed value in 'step_3' by A, here hand-picked.
    :param beta: Computed value in 'step_2' by B, here hand-picked.
    """
    beta_is_enc = [
        dgk_full.unsafe_encrypt(beta[i], apply_encoding=False)
        for i in range(COMPARISON_BIT_LENGTH)
    ]
    for i in range(COMPARISON_BIT_LENGTH):
        alpha_xor_beta = alpha[i] ^ beta[i]
        alpha_is_xor_beta_is_enc = Initiator.step_4d(alpha, beta_is_enc)
        assert alpha_xor_beta == dgk_full.decrypt(alpha_is_xor_beta_is_enc[i])


@pytest.mark.parametrize("x_enc, y_enc", list(zip(TEST_VALS_SMALLER, TEST_VALS_BIGGER)))
def test_step_4e(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    Assert that the value of $[w_i]$ is set correctly. We compute this slightly
    different than in 'step_4e', namely we make use of the multiplicative inverse and
    homomorphism to reduce the equation in a different manner.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    z_enc, r = Initiator.step_1(x_enc, y_enc, COMPARISON_BIT_LENGTH, paillier)
    z, beta = KeyHolder.step_2(z_enc, COMPARISON_BIT_LENGTH, paillier)
    alpha = Initiator.step_3(r, COMPARISON_BIT_LENGTH)
    d_enc = KeyHolder.step_4a(z, dgk_full, paillier, COMPARISON_BIT_LENGTH)
    beta_is_enc = KeyHolder.step_4b(beta, COMPARISON_BIT_LENGTH, dgk_full)
    d_enc = Initiator.step_4c(d_enc, r, dgk_full, paillier)
    alpha_is_xor_beta_is_enc = Initiator.step_4d(alpha, beta_is_enc)
    w_is_enc, _ = Initiator.step_4e(r, alpha, alpha_is_xor_beta_is_enc, d_enc, paillier)
    alpha_tilde_test = (r - paillier_n) % (1 << COMPARISON_BIT_LENGTH)
    alpha_tilde_test_bits = to_bits(alpha_tilde_test, COMPARISON_BIT_LENGTH)
    beta_bits = to_bits(beta, COMPARISON_BIT_LENGTH)
    d = int(dgk_full.decrypt(d_enc))

    for i in range(COMPARISON_BIT_LENGTH):
        if alpha[i] == alpha_tilde_test_bits[i]:
            assert dgk_full.decrypt(w_is_enc[i]) == alpha[i] ^ beta_bits[i]
        else:
            assert dgk_full.decrypt(w_is_enc[i]) == alpha[i] ^ beta_bits[i] - d


@pytest.mark.parametrize("x_enc, y_enc", list(zip(TEST_VALS_SMALLER, TEST_VALS_BIGGER)))
def test_step_4f(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext) -> None:
    r"""
    We basically test whether multiplication by a bit $i$ that is left-shifted
    every iteration is the same as multiplcation by $2^i$. We can't check whether
    $[w_i]^{2^i}$ works, as exponentation of PaillierCiphertexts is not implemented.

    :param x_enc: Encryption of first input.
    :param y_enc: Encryption of second input, satisfying x_enc < y_enc.
    """
    z_enc, r = Initiator.step_1(x_enc, y_enc, COMPARISON_BIT_LENGTH, paillier)
    z, beta = KeyHolder.step_2(z_enc, COMPARISON_BIT_LENGTH, paillier)
    alpha = Initiator.step_3(r, COMPARISON_BIT_LENGTH)
    d_enc = KeyHolder.step_4a(z, dgk_full, paillier, COMPARISON_BIT_LENGTH)
    beta_is_enc = KeyHolder.step_4b(beta, COMPARISON_BIT_LENGTH, dgk_full)
    d_enc = Initiator.step_4c(d_enc, r, dgk_full, paillier)
    alpha_is_xor_beta_is_enc = Initiator.step_4d(alpha, beta_is_enc)
    w_is_enc, _ = Initiator.step_4e(r, alpha, alpha_is_xor_beta_is_enc, d_enc, paillier)
    w_test = [
        int(dgk_full.decrypt(w_is_enc[i])) * (2**i) % dgk_full.public_key.u
        for i in range(COMPARISON_BIT_LENGTH)
    ]
    w_is_enc = Initiator.step_4f(w_is_enc)
    for i in range(COMPARISON_BIT_LENGTH):
        assert w_test[i] == int(dgk_full.decrypt(w_is_enc[i], apply_encoding=False))


@pytest.mark.parametrize("x_enc, y_enc", list(zip(TEST_VALS_SMALLER, TEST_VALS_BIGGER)))
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
    z_enc, r = Initiator.step_1(x_enc, y_enc, COMPARISON_BIT_LENGTH, paillier)
    z, beta = KeyHolder.step_2(z_enc, COMPARISON_BIT_LENGTH, paillier)
    alpha = Initiator.step_3(r, COMPARISON_BIT_LENGTH)
    d_enc = KeyHolder.step_4a(z, dgk_full, paillier, COMPARISON_BIT_LENGTH)
    beta_is_enc = KeyHolder.step_4b(beta, COMPARISON_BIT_LENGTH, dgk_full)
    d_enc = Initiator.step_4c(d_enc, r, dgk_full, paillier)
    alpha_is_xor_beta_is_enc = Initiator.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = Initiator.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, paillier
    )
    w_is_enc = Initiator.step_4f(w_is_enc)
    s, delta_a = Initiator.step_4g()
    c_is_enc = Initiator.step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, dgk_full
    )
    d = int(dgk_full.decrypt(d_enc))
    beta_bits = to_bits(beta, COMPARISON_BIT_LENGTH)

    for i in range(COMPARISON_BIT_LENGTH):
        temp = int(
            s
            + alpha[i]
            + (alpha_tilde[i] - alpha[i]) * d
            - beta_bits[i]
            + 3 * sum(int(dgk_full.decrypt(wj)) for wj in w_is_enc[i + 1 :])
        )
        assert (
            temp % dgk_full.public_key.u
            == int(dgk_full.decrypt(c_is_enc[i + 1])) % dgk_full.public_key.u
        )


@pytest.mark.parametrize("x_enc, y_enc", list(zip(TEST_VALS_SMALLER, TEST_VALS_BIGGER)))
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
    z_enc, r = Initiator.step_1(x_enc, y_enc, COMPARISON_BIT_LENGTH, paillier)
    z, beta = KeyHolder.step_2(z_enc, COMPARISON_BIT_LENGTH, paillier)
    alpha = Initiator.step_3(r, COMPARISON_BIT_LENGTH)
    d_enc = KeyHolder.step_4a(z, dgk_full, paillier, COMPARISON_BIT_LENGTH)
    beta_is_enc = KeyHolder.step_4b(beta, COMPARISON_BIT_LENGTH, dgk_full)
    d_enc = Initiator.step_4c(d_enc, r, dgk_full, paillier)
    alpha_is_xor_beta_is_enc = Initiator.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = Initiator.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, paillier
    )
    w_is_enc = Initiator.step_4f(w_is_enc)
    s, delta_a = Initiator.step_4g()
    c_is_enc = Initiator.step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, dgk_full
    )
    c_is_enc = Initiator.step_4i(c_is_enc, dgk_full)
    delta_b = KeyHolder.step_4j(c_is_enc, dgk_full)

    for i in range(COMPARISON_BIT_LENGTH):
        if dgk_full.is_zero(
            c_is_enc[i + 1]
        ):  # Plus 1 here to correct the element added in Initiator.step_4h
            assert delta_b == 1


@pytest.mark.parametrize("z, delta_b", TEST_5)
def test_step_5(z: int, delta_b: int) -> None:
    r"""
    We compute $z \div 2^l$ slightly different than in 'step_5'. Namely
    we have eliminated the if-statement and have used a masking technique.

    :param z: Result of 'step_1', here hand-picked.
    :param delta_b: Bit result of 'step_4j'. Here the value is hand-picked.
    """
    l = COMPARISON_BIT_LENGTH
    n = paillier.public_key.n
    zeta_1_enc, zeta_2_enc, delta_b_enc = KeyHolder.step_5(
        z, COMPARISON_BIT_LENGTH, delta_b, paillier
    )
    assert paillier.decrypt(zeta_1_enc) == z // (2**l)
    assert paillier.decrypt(zeta_2_enc) == int(z < (n - 1) // 2) * (
        (z + n) // (2**l)
    ) + int(z >= (n - 1) // 2) * (z // (2**l))
    assert paillier.decrypt(delta_b_enc) == delta_b


@pytest.mark.parametrize("delta_a, delta_b_enc", TEST_6)
def test_step_6(delta_a: int, delta_b_enc: PaillierCiphertext) -> None:
    r"""
    Test whether $[[\beta < \alpha]]$ is computed correctly. We
    have eliminated the if-statement and have used a masking technique.
    We also used the value of $\delta_B$ directly, instead of using the
    encrypted value as should be used in the protocol.

    :param delta_a: Bit value computed in 'step_4g', here this is hand-picked.
    :param delta_b_enc: Encrypted bit computed in 'step_5', here this is hand-picked.
    """
    beta_lt_alpha_enc = Initiator.step_6(delta_a, delta_b_enc)
    delta_a_true_part = delta_a * delta_b_enc
    decryption_delta_b_enc = int(paillier.decrypt(delta_b_enc))
    delta_a_false_part = int(not delta_a) * (1 - decryption_delta_b_enc)
    assert paillier.decrypt(beta_lt_alpha_enc) == paillier.decrypt(
        delta_a_true_part + delta_a_false_part
    )


@pytest.mark.parametrize("x_enc, y_enc", list(zip(TEST_VALS_SMALLER, TEST_VALS_BIGGER)))
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
    z_enc, r = Initiator.step_1(x_enc, y_enc, COMPARISON_BIT_LENGTH, paillier)
    z, beta = KeyHolder.step_2(z_enc, COMPARISON_BIT_LENGTH, paillier)
    alpha = Initiator.step_3(r, COMPARISON_BIT_LENGTH)
    d_enc = KeyHolder.step_4a(z, dgk_full, paillier, COMPARISON_BIT_LENGTH)
    beta_is_enc = KeyHolder.step_4b(beta, COMPARISON_BIT_LENGTH, dgk_full)
    d_enc = Initiator.step_4c(d_enc, r, dgk_full, paillier)
    alpha_is_xor_beta_is_enc = Initiator.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = Initiator.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, paillier
    )
    w_is_enc = Initiator.step_4f(w_is_enc)
    s, delta_a = Initiator.step_4g()
    c_is_enc = Initiator.step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, dgk_full
    )
    c_is_enc = Initiator.step_4i(c_is_enc, dgk_full)
    delta_b = KeyHolder.step_4j(c_is_enc, dgk_full)
    zeta_1_enc, zeta_2_enc, delta_b_enc = KeyHolder.step_5(
        z, COMPARISON_BIT_LENGTH, delta_b, paillier
    )
    beta_lt_alpha_enc = Initiator.step_6(delta_a, delta_b_enc)
    x_leq_y_enc = Initiator.step_7(
        zeta_1_enc,
        zeta_2_enc,
        r,
        COMPARISON_BIT_LENGTH,
        beta_lt_alpha_enc,
        paillier,
    )
    x_leq_y = (z // (2**COMPARISON_BIT_LENGTH)) - (
        (r // (2**COMPARISON_BIT_LENGTH)) + (int(beta < from_bits(alpha)))
    ) % paillier.public_key.n_squared

    assert x_leq_y == paillier.decrypt(x_leq_y_enc)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "x, y", list(zip(TEST_VALS_SMALLER_PLAINTEXT, TEST_VALS_BIGGER_PLAINTEXT))
)
async def test_smaller_than(
    x: int,
    y: int,
    paillier_strict: Paillier,
    playerpair_with_dict_communication: tuple[Initiator, KeyHolder],
) -> None:
    """
    Assert that the secure comparison returns the expected result when the
    input satisfies a "smaller than" relation, interactive and non-interactive.

    :param x: First input.
    :param y: Second input, satisfying x < y.
    :param paillier_strict: Paillier scheme.
    :param playerpair_with_dict_communication: Initiator-keyholder pair that
        is configured with communication.
    """
    initiator, keyholder = playerpair_with_dict_communication
    x_enc = paillier_strict.unsafe_encrypt(x)
    y_enc = paillier_strict.unsafe_encrypt(y)
    dgk_full_ = keyholder.scheme_dgk

    x_leq_y_enc = run_comparison(x_enc, y_enc, paillier_strict, dgk_full_)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert x_leq_y == 1

    x_leq_y_enc = await run_interactive_comparison(x_enc, y_enc, initiator, keyholder)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert x_leq_y == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "x, y", list(zip(TEST_VALS_BIGGER_PLAINTEXT, TEST_VALS_SMALLER_PLAINTEXT))
)
async def test_greater_than(
    x: int,
    y: int,
    paillier_strict: Paillier,
    playerpair_with_dict_communication: tuple[Initiator, KeyHolder],
) -> None:
    """
    Assert that the secure comparison returns the expected result when the
    input satisfies a "greater than" relation, interactive and non-interactive.

    :param x: First input.
    :param y: Second input, satisfying x > y.
    :param paillier_strict: Paillier scheme.
    :param playerpair_with_dict_communication: Initiator-keyholder pair that
        is configured with communication.
    """
    initiator, keyholder = playerpair_with_dict_communication
    x_enc = paillier_strict.unsafe_encrypt(x)
    y_enc = paillier_strict.unsafe_encrypt(y)
    dgk_full_ = keyholder.scheme_dgk

    x_leq_y_enc = run_comparison(x_enc, y_enc, paillier_strict, dgk_full_)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert x_leq_y == 0

    x_leq_y_enc = await run_interactive_comparison(x_enc, y_enc, initiator, keyholder)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert x_leq_y == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "x, y", list(zip(TEST_VALS_BIGGER_PLAINTEXT, TEST_VALS_BIGGER_PLAINTEXT))
)
async def test_equal_to(
    x: int,
    y: int,
    paillier_strict: Paillier,
    playerpair_with_dict_communication: tuple[Initiator, KeyHolder],
) -> None:
    """
    Assert that the secure comparison returns the expected result when the
    input satisfies a "is equal to" relation, interactive and non-interactive.

    :param x: First input.
    :param y: Second input, satisfying x == y.
    :param paillier_strict: Paillier scheme.
    :param playerpair_with_dict_communication: Initiator-keyholder pair that
        is configured with communication.
    """
    initiator, keyholder = playerpair_with_dict_communication
    x_enc = paillier_strict.unsafe_encrypt(x)
    y_enc = paillier_strict.unsafe_encrypt(y)
    dgk_full_ = keyholder.scheme_dgk

    x_leq_y_enc = run_comparison(x_enc, y_enc, paillier_strict, dgk_full_)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert x_leq_y == 1

    x_leq_y_enc = await run_interactive_comparison(x_enc, y_enc, initiator, keyholder)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert x_leq_y == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("x, y, boolean_result", TEST_CONVERSION_TO_BOOL)
async def test_conversion_to_boolean(
    x: int,
    y: int,
    boolean_result: bool,
    paillier_strict: Paillier,
    playerpair_with_dict_communication: tuple[Initiator, KeyHolder],
) -> None:
    """
    Test conversion from decrypted result to boolean. If this test fails,
    the issue is probably in a depencency; however, the users of this package
    expect that the decrypted result works properly as a boolean and so we
    should know. Tests for interactive and non-interactive.

    :param x: First input.
    :param y: Second input.
    :param boolean_result: Boolean result of the comparison of x_enc and
        y_enc, e.g. (x <= y).
    :param paillier_strict: Paillier scheme.
    :param playerpair_with_dict_communication: Initiator-keyholder pair that
        is configured with communication.
    """
    initiator, keyholder = playerpair_with_dict_communication
    x_enc = paillier_strict.unsafe_encrypt(x)
    y_enc = paillier_strict.unsafe_encrypt(y)
    dgk_full_ = keyholder.scheme_dgk

    x_leq_y_enc = run_comparison(x_enc, y_enc, paillier_strict, dgk_full_)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert bool(x_leq_y) == boolean_result

    x_leq_y_enc = await run_interactive_comparison(x_enc, y_enc, initiator, keyholder)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert bool(x_leq_y) == boolean_result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "x, y", list(zip(TEST_VALS_SMALLER_PLAINTEXT, TEST_VALS_BIGGER_PLAINTEXT))
)
async def test_smaller_than_unencrypted_inputs(
    x: int,
    y: int,
    paillier_strict: Paillier,
    playerpair_with_dict_communication: tuple[Initiator, KeyHolder],
) -> None:
    """
    Assert that the secure comparison returns the expected result when the
    input satisfies a "smaller than" relation, interactive.

    :param x: First input.
    :param y: Second input, satisfying x < y.
    :param paillier_strict: Paillier scheme.
    :param playerpair_with_dict_communication: Initiator-keyholder pair that
        is configured with communication.
    """
    initiator, keyholder = playerpair_with_dict_communication

    x_leq_y_enc = await run_interactive_comparison(x, y, initiator, keyholder)
    x_leq_y = paillier_strict.decrypt(x_leq_y_enc)
    assert x_leq_y == 1


@pytest.mark.asyncio
async def test_parallel_runs(
    paillier_strict: Paillier,
    playerpair_with_dict_communication: tuple[Initiator, KeyHolder],
) -> None:
    """
    Test multiple runs of `perform_secure_comparison simultaneously.

    :param paillier_strict: Paillier scheme.
    :param playerpair_with_dict_communication: Initiator-keyholder pair that
        is configured with communication.
    """
    initiator, keyholder = playerpair_with_dict_communication

    x_enc_1 = paillier_strict.unsafe_encrypt(11)
    x_enc_2 = paillier_strict.unsafe_encrypt(41)
    y_enc_1 = paillier_strict.unsafe_encrypt(12)
    y_enc_2 = paillier_strict.unsafe_encrypt(41)

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

    assert paillier_strict.decrypt(x_leq_y_1) == 1 == paillier_strict.decrypt(x_leq_y_2)


@pytest.mark.asyncio
async def test_if_different_schemes_then_raises_valueerror(
    playerpair_with_dict_communication: tuple[Initiator, KeyHolder],
) -> None:
    """
    A value error should be raised when the paillier or DGK scheme that is received conflicts with the readily initialized scheme.

    :param playerpair_with_dict_communication: Initiator-keyholder pair that
        is configured with communication.
    """
    # pylint: disable=protected-access
    initiator, keyholder = playerpair_with_dict_communication
    initiator._scheme_paillier = paillier

    task_initiator = asyncio.create_task(initiator.receive_encryption_schemes())
    task_keyholder = asyncio.create_task(keyholder.make_and_send_encryption_schemes())

    with pytest.raises(ValueError, match=".*Paillier"):
        await asyncio.gather(*(task_initiator, task_keyholder))

    initiator._scheme_paillier = keyholder._scheme_paillier
    initiator._scheme_dgk = dgk_full

    task_initiator = asyncio.create_task(initiator.receive_encryption_schemes())
    task_keyholder = asyncio.create_task(keyholder.make_and_send_encryption_schemes())

    with pytest.raises(ValueError, match=".*DGK"):
        await asyncio.gather(*(task_initiator, task_keyholder))
