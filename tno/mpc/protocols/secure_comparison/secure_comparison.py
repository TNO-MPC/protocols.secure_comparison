"""
Implementation of secure comparison protocol as given in https://eprint.iacr.org/2018/1100.pdf
Protocol 3 (with fixes).

We implement all (sub)steps separately, and do not handle communication or which player performs
what action.

We implement the protocol using Paillier only, i.e., in our implementation $[[m]]$ and $[m]$ are
both the same Paillier scheme.
"""

from secrets import choice, randbelow
from typing import Any, cast, List, Tuple, Union

from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext


def to_bits(integer: int, bit_length: int) -> List[int]:
    """
    Convert a given integer to a list of bits, with the least significant bit first, and the most
    significant bit last.

    :param integer: Integer to be converted to bits.
    :param bit_length: Amount of bits to which the integer should be converted.
    :return: Bit representation of the integer in bit_length bits. Least significant bit first,
        most significant last.
    """
    bits = [0 for _ in range(bit_length)]
    for bit_index in range(bit_length):
        bits[bit_index] = integer & 1
        integer >>= 1
    return bits


def from_bits(bits: List[int]) -> int:
    """
    Convert a set of bits, least significant bit first to an integer.

    :param bits: List of bits, least significant bit first.
    :return: Integer representation of the bits.
    """
    base = 1
    integer = 0
    for bit in bits:
        if bit == 1:
            integer += base
        base *= 2
    return integer


def shuffle(values: List[Any]) -> List[Any]:
    r"""
    Shuffle the list in random order.

    :param values: List of objets that is to be shuffled.
    :return: Shuffled version of the input list.
    """
    values = values.copy()
    shuffled_values = []
    while len(values):
        this_value = choice(values)
        values.remove(this_value)
        shuffled_values.append(this_value)
    return shuffled_values


def step_1(
    x_enc: PaillierCiphertext, y_enc: PaillierCiphertext, l: int, scheme: Paillier
) -> Tuple[PaillierCiphertext, int]:
    r"""
    $A$ chooses a random number $r, 0 \leq r < N$, and computes
    $$[[z]] \leftarrow [[y - x + 2^l + r]] = [[x]] \cdot [[y]]^{-1} \cdot [[2^l + r]] \mod N^2.$$

    :param x_enc: Encrypted value of $x$: $[[x]]$.
    :param y_enc: Encrypted value of $y$: $[[y]]$.
    :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x$, $y$ that will be given as
        input to this method.
    :param scheme: Paillier encryption scheme.
    :return: Tuple containing as first entry the encrypted value of $z$:
        $[[z]] \leftarrow [[y - x + 2^l + r]] = [[y]] \cdot [[x]]^{-1} \cdot [[2^l + r]] \mod
        N^2$. The second entry is the randomness value $r$.
    """
    assert (1 >> l) < scheme.public_key.n
    r = randbelow(scheme.public_key.n)
    # Note: the paper has a typo here, it says x - y, i/o y - x.
    return (
        y_enc - x_enc + scheme.encrypt((1 << l) + r, apply_encoding=False),
        r,
    )


def step_2(z_enc: PaillierCiphertext, l: int, scheme: Paillier) -> Tuple[int, int]:
    r"""
    $B$ decrypts $[[z]]$, and computes $\beta = z \mod 2^l$.

    :param z_enc: Encrypted value of $z$: $[[z]]$.
    :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be given as input
        to this method.
    :param scheme: Paillier encryption scheme.
    :return: Tuple containing as first entry the plaintext value of $z$. The second entry is the
        value $\beta = z \mod 2^l$.
    """
    z = cast(int, scheme.decrypt(z_enc, apply_encoding=False))
    return z, z % (1 << l)


def step_3(r: int, l: int) -> List[int]:
    r"""
    $A$ computes $\alpha = r \mod 2^l$.

    :param r: The randomness value $r$ from step 1.
    :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be given as input
        to this method.
    :return: Value $\alpha = r \mod 2^l$ as bits.
    """
    return to_bits(r % (1 << l), l)


def step_4a(z: int, scheme: Paillier) -> PaillierCiphertext:
    r"""
    $B$ computes the encrypted bit $[d]$ where $d = (z < (N - 1)/2)$ is the bit informing $A$
    whether a carryover has occurred.

    :param z: Plaintext value of $z$.
    :param scheme: Paillier encryption scheme.
    :return: Encrypted value of the bit $d = (z < (N - 1)/2)$: $[d]$.
    """
    return scheme.encrypt(int(z < (scheme.public_key.n - 1) // 2))


def step_4b(beta: int, l: int, scheme: Paillier) -> List[PaillierCiphertext]:
    r"""
    $B$ computes the encrypted bits $[\beta_i], 0 \leq i < l$ to $A$.

    :param beta: The value $\beta$ from step 2.
    :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be given as input
        to this method.
    :param scheme: Paillier encryption scheme.
    :return: List containing the encrypted values of the bits $\beta_i$: $[\beta_i], 0 \leq i < l$
        to $A$.
    """
    return list(map(scheme.encrypt, to_bits(beta, l)))


def step_4c(d_enc: PaillierCiphertext, r: int, scheme: Paillier) -> PaillierCiphertext:
    r"""
    $A$ corrects $[d]$ by setting $[d] \leftarrow [0]$ whenever $0 \leq r < (N - 1)/2$.

    :param d_enc: Encrypted value of $d$: $[d]$.
    :param r: The randomness value $r$ from step 1.
    :param scheme: Paillier encryption scheme.
    :return: Corrected encrypted value of $d$: $[d]$. If $0 \leq r < (N - 1)/2$, then
        $[d] \leftarrow [0]$, else $[d]$ remains unaltered.
    """
    if r < (scheme.public_key.n - 1) // 2:
        d_enc = scheme.encrypt(0)
    return d_enc


def step_4d(
    alpha: List[int], beta_is_enc: List[PaillierCiphertext]
) -> List[PaillierCiphertext]:
    r"""
    For each $i, 0 \leq i < l$, $A$ computes $[\alpha_i \oplus \beta_i]$ as follows:
    if $\alpha_i = 0$ then $[\alpha_i \oplus \beta_i] \leftarrow [\beta_i]$ else
    $[\alpha_i \oplus \beta_i] \leftarrow [1] \cdot [\beta_i]^{-1} \mod n$.

    :param alpha: The value $\alpha$ from step 3.
    :param beta_is_enc: List containing the encrypted values of $\beta_i$:
        $[\beta_i], 0 \leq i < l$.
    :return: List containing the encrypted values of the bits
        $\alpha_i \oplus \beta_i$: $[\alpha_i \oplus \beta_i], 0 \leq i < l$.
    """

    def compute_xor(alpha_i: int, beta_i_enc: PaillierCiphertext) -> PaillierCiphertext:
        r"""
        Compute $[\alpha_i \oplus \beta_i]$.

        :param alpha_i: The $i$-th bit of $\alpha$: $\alpha_i$.
        :param beta_i_enc: The encrypted $i$-th bit of $\beta$: $[\beta_i]$.
        :return: Encrypted value of $\alpha_i \oplus \beta_i$: $[\alpha_i \oplus \beta_i]$.
        """
        if alpha_i == 0:
            return beta_i_enc
        # else (alpha_i == 1)
        return 1 - beta_i_enc

    return list(
        map(
            compute_xor,
            alpha,
            beta_is_enc,
        )
    )


def step_4e(
    r: int,
    alpha: List[int],
    alpha_is_xor_beta_is_enc: List[PaillierCiphertext],
    d_enc: PaillierCiphertext,
    scheme: Paillier,
) -> Tuple[List[PaillierCiphertext], List[int]]:
    r"""
    A computes $\tilde{\alpha} = (r - N) \mod 2^l$, the corrected value of $\alpha$ in case a
    carry-over actually did occur and adjusts $[\alpha_i \oplus \beta_i]$ for each $i$:
    If $\alpha_i = \tilde{\alpha}_i$ then $[w_i] \leftarrow [\alpha_i \oplus \beta_i]$
    else $[w_i] \leftarrow [\alpha_i \oplus \beta_i] \cdot [d]^{-1} \mod n$

    :param r: The randomness value $r$ from step 1.
    :param alpha: The value $\alpha$ from step 3.
    :param alpha_is_xor_beta_is_enc: List containing the encrypted values of the bits
        $\alpha_i \oplus \beta_i$: $[\alpha_i \oplus \beta_i], 0 \leq i < l$.
    :param d_enc: Encrypted value of $d$: $[d]$.
    :param scheme: Paillier encryption scheme.
    :return: Tuple containing as first entry a list containing the encrypted values of the bits
        $w_i$: $[w_i], 0 \leq i < l$.
        The second entry is the value $\tilde{\alpha} = (r - N) \mod 2^l$ as bits.
    """
    l = len(alpha_is_xor_beta_is_enc)

    def compute_w(
        alpha_i: int, alpha_tilde_i: int, alpha_i_xor_beta_i_enc: PaillierCiphertext
    ) -> PaillierCiphertext:
        r"""
        Compute $[w_i]$.

        :param alpha_i: The $i$-th bit of $\alpha$: $\alpha_i$.
        :param alpha_tilde_i: The $i$-th bit of $\tilde{\alpha}$: $\tilde{\alpha}_i$.
        :param alpha_i_xor_beta_i_enc: Encrypted value of the bit $\alpha_i \oplus \beta_i$:
            $[\alpha_i \oplus \beta_i]$.
        :return: Encrypted value of $w_i$: $[w_i]$.
        """
        if alpha_i == alpha_tilde_i:
            return alpha_i_xor_beta_i_enc
        # else
        return alpha_i_xor_beta_i_enc - d_enc

    alpha_tilde = to_bits(int((r - scheme.public_key.n) % (1 << l)), l)
    return (
        list(
            map(
                compute_w,
                alpha,
                alpha_tilde,
                alpha_is_xor_beta_is_enc,
            )
        ),
        alpha_tilde,
    )


def step_4f(w_is_enc: List[PaillierCiphertext]) -> List[PaillierCiphertext]:
    r"""
    For each $i, 0 \leq i < l$, $A$ computes $[w_i] \leftarrow [w_i]^{2^i} \mod n$ such that these
    values will not interfere each other when added.

    :param w_is_enc: List containing the encrypted values of the bits $w_i$: $[w_i], 0 \leq i < l$.
    :return: List containing the encrypted values of the bits $w_i$: $[w_i], 0 \leq i < l$.
    """
    base = 1

    def compute_w(w_i_enc: PaillierCiphertext) -> PaillierCiphertext:
        r"""
        Compute $[w_i]$.

        :param w_i_enc: Encrypted value of $w_i$: $[w_i]$.
        :return: Encrypted value of $w_i$: $[w_i]$.
        """
        nonlocal base
        w_i_enc = w_i_enc * base
        base <<= 1
        return w_i_enc

    return list(map(compute_w, w_is_enc))


def step_4g() -> Tuple[int, int]:
    r"""
    $A$ chooses a uniformly random bit $\delta_A$ and computes $s = 1 - 2 \cdot \delta_A$.

    :return: Tuple containing as first entry the value $s = 1 - 2 \cdot \delta_A$.
        The second entry is the value $\delta_A$.
    """
    delta_a = randbelow(2)
    return 1 - 2 * delta_a, delta_a


def step_4h(
    s: int,
    alpha: List[int],
    alpha_tilde: List[int],
    d_enc: PaillierCiphertext,
    beta_is_enc: List[PaillierCiphertext],
    w_is_enc: List[PaillierCiphertext],
    delta_a: int,
    scheme: Paillier,
) -> List[PaillierCiphertext]:
    r"""
    For each $i, 0 \leq i < l$, $A$ computes $[c_i] = [s] \cdot [\alpha_i] \cdot
    [d]^{\tilde{\alpha}_i-\alpha_i} \cdot [\beta_i]^{-1} \cdot (\Pi^{l-1}_{j=i+1}[w_j])^3 \mod n$.
    We add an additional value $[c_{-1}]$, with
    $c_{-1}=\delta_A + \Sigma^{l-1}_{i=0}(x_i \oplus y_i)$ to also make the scheme work in case
    of equality of $x$ and $y$.

    :param s: The value $s$ from step 4g.
    :param alpha: The value $\alpha$ from step 3.
    :param alpha_tilde: The value $\tilde{\alpha}$ from step 4e.
    :param d_enc: Encrypted value of $d$: $[d]$.
    :param beta_is_enc: List containing the encrypted values of the bits $\beta_i$:
        $[\beta_i], 0 \leq i < l$.
    :param w_is_enc: List containing the encrypted values of the bits $w_i$: $[w_i], 0 \leq i < l$.
    :param delta_a: The value $\delta_A$ from step 4g.
    :param scheme: Paillier encryption scheme.
    :return: List containing the encrypted values of the bits $c_i$: $[c_i] = [s] \cdot [\alpha_i]
        \cdot [d]^{\tilde{\alpha}_i-\alpha_i} \cdot [\beta_i]^{-1}
        \cdot (\Pi^{l-1}_{j=i+1}[w_j])^3 \mod n, 0 \leq i < l$.
    """
    l = len(beta_is_enc)

    c_is_enc = [scheme.encrypt(s) for _ in range(l)]
    w_is_enc_sum: Union[int, PaillierCiphertext] = 0

    # pre-compute 3 options for d_enc * (alpha_i, alpha_tilde_i) to improve efficiency
    d_enc_mult_table = {
        -1: d_enc * -1,
        0: d_enc * 0,
        1: d_enc * 1,
    }

    for i, alpha_i, alpha_tilde_i in zip(
        range(l - 1, -1, -1),
        reversed(alpha),
        reversed(alpha_tilde),
    ):
        c_is_enc[i] += (
            int(alpha_i)
            + d_enc_mult_table[alpha_tilde_i - alpha_i]
            - beta_is_enc[i]
            + 3 * w_is_enc_sum
        )
        w_is_enc_sum += w_is_enc[i]
    # we use here the fix from the paper to make equality work
    c_is_enc.insert(0, cast(PaillierCiphertext, delta_a + w_is_enc_sum))
    return c_is_enc


def step_4i(
    c_is_enc: List[PaillierCiphertext], scheme: Paillier, do_shuffle: bool = True
) -> List[PaillierCiphertext]:
    r"""
    $A$ blinds the numbers $c_i$ by raising them to a random non-zero exponent
    $r_i \in \{1,\ldots,u-1\}$, and refreshing the randomness with a second exponent $r'_i$ of $2t$
    bits: $[c_i] \leftarrow [c_i]^{r_i} \cdot h^{r'_i} \mod n$.

    :param c_is_enc: List containing the encrypted values of the bits $c_i$: $[c_i], 0 \leq i < l$.
    :param scheme: Paillier encryption scheme.
    :param do_shuffle: Boolean parameter stating whether or not the bits should be shuffled
        randomly. (Default: True).
    :return: List containing the encrypted values of the masked bits $c_i$: $[c_i], 0 \leq i < l$.
    """
    u = scheme.public_key.n

    def mask_and_rerandomize(c_i_enc: PaillierCiphertext) -> PaillierCiphertext:
        r"""
        Compute $[c_i]$.

        :param c_i_enc: Encrypted value of the bit $c_i$: $[c_i]$.
        :return: Encrypted value of the bit $c_i$: $[c_i]$.
        """
        c_i_enc *= randbelow(u - 1) + 1
        c_i_enc.randomize()
        return c_i_enc

    c_is_enc_masked = list(map(mask_and_rerandomize, c_is_enc))
    return shuffle(c_is_enc_masked) if do_shuffle else c_is_enc_masked


def step_4j(c_is_enc: List[PaillierCiphertext], scheme: Paillier) -> int:
    r"""
    $B$ checks whether one of the numbers $c_i$ is decrypted to zero. If he finds one,
    $\delta_B \leftarrow 1$, else $\delta_B \leftarrow 0$.

    :param c_is_enc: List containing the encrypted values of the bits $c_i$: $[c_i], 0 \leq i < l$.
    :param scheme: Paillier encryption scheme.
    :return: Value $\delta_B$.
    """
    return int(any(map(lambda c_i_enc: scheme.decrypt(c_i_enc) == 0, c_is_enc)))


def step_5(
    z: int, l: int, delta_b: int, scheme: Paillier
) -> Tuple[PaillierCiphertext, PaillierCiphertext, PaillierCiphertext]:
    r"""
    $B$ computes $\zeta_1 = z \div 2^l$ and encrypts it to $[[\zeta_1]]$ and computes
    $\zeta_2 = (z + N) \div 2^l$ and encrypts it to $[[\zeta_2]]$. $B$ also encrypts $\delta_B$ to
    $[[\delta_B]]$.

    :param z: Plaintext value of $z$.
    :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be given as input
        to this method.
    :param delta_b: The value $\delta_B$ from step 4j.
    :param scheme: Paillier encryption scheme.
    :return: A tuple with the first entry being the encrypted value of $\zeta_1$: $[[\zeta_1]]$.
        The second entry is the encrypted value of $\zeta_2$: $[[\zeta_2]]$. The third entry is the
        encrypted value of $\delta_B$: $[[\delta_B]]$.
    """
    # We use the fix mentioned in the paper here, to also make this work in case of overflow
    zeta_1_enc = scheme.encrypt(z // (1 << l))
    zeta_2_enc = (
        scheme.encrypt((z + scheme.public_key.n) // (1 << l))
        if z < (scheme.public_key.n - 1) // 2
        else scheme.encrypt(z // (1 << l))
    )
    return zeta_1_enc, zeta_2_enc, scheme.encrypt(delta_b)


def step_6(delta_a: int, delta_b_enc: PaillierCiphertext) -> PaillierCiphertext:
    r"""
    $A$ computes $[[(\beta < \alpha)]]$ as follows: if $\delta_A = 1$ then
    $[[(\beta < \alpha)]] \leftarrow [[\delta_B]]$ else
    $[[(\beta < \alpha)]] \leftarrow [[1]] \cdot [[\delta_B]]^{-1} \mod N^2$.

    :param delta_a: The value $\delta_A$ from step 4g.
    :param delta_b_enc: Encrypted value of $\delta_B$: $[[\delta_B]]$.
    :return: Encrypted value of $(\beta < \alpha)$: $[[(\beta < \alpha)]]$.
    """
    if delta_a == 1:
        return delta_b_enc
    return 1 - delta_b_enc


def step_7(
    zeta_1_enc: PaillierCiphertext,
    zeta_2_enc: PaillierCiphertext,
    r: int,
    l: int,
    beta_lt_alpha_enc: PaillierCiphertext,
    scheme: Paillier,
) -> PaillierCiphertext:
    r"""
    $A$ computes $[[(x \leq y)]] \leftarrow
    [[\zeta]] \cdot ([[ r \div 2^l]] \cdot [[(\beta < \alpha)]])^{-1} \mod N^2$, where
    $\zeta = \zeta_1$, if $r < (N - 1) / 2$, else $\zeta = \zeta_2$.

    :param zeta_1_enc: Encrypted value of $\zeta_1$: $[[\zeta_1]]$.
    :param zeta_2_enc: Encrypted value of $\zeta_2$: $[[\zeta_2]]$.
    :param r: The randomness value $r$ from step 1.
    :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be given as input
        to this method.
    :param beta_lt_alpha_enc: Encrypted value of $(\beta < \alpha)$: $[[(\beta < \alpha)]]$.
    :param scheme: Paillier encryption scheme.
    :return: Encrypted value of $(x \leq y)$: $[[(x \leq y)]]$. This is the final result of the
        computation.
    """
    # We use the fix mentioned in the paper here, to also make this work in case of overflow
    zeta_enc = zeta_1_enc if r < (scheme.public_key.n - 1) // 2 else zeta_2_enc
    return zeta_enc - (scheme.encrypt(r // (1 << l)) + beta_lt_alpha_enc)
