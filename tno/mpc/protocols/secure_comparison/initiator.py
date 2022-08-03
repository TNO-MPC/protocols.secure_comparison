"""Initiator of protocol, i.e. performs step 1. Alice; A in the paper."""

from secrets import choice, randbelow
from typing import Any, List, Optional, Tuple, Union, cast

from tno.mpc.encryption_schemes.dgk import DGK, DGKCiphertext
from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext

from .communicator import Communicator
from .utils import to_bits


class Initiator:
    """
    Player Alice in the secure comparison protocol, initiates.
    """

    def __init__(
        self,
        l_maximum_bit_length: int,
        communicator: Optional[Communicator] = None,
        other_party: str = "",
        scheme_paillier: Optional[Paillier] = None,
        scheme_dgk: Optional[DGK] = None,
        session_id: int = 0,
    ) -> None:
        r"""
        :param l_maximum_bit_length: maximum bit length used to constrain variables ($l$).
        :param communicator: object for handling communication with the KeyHolder during the protocol.
        :param other_party: identifier of the other party
        :param scheme_paillier: Paillier encryption scheme (without secret key).
        :param scheme_dgk: DGK encryption scheme (without secret key).
        :param session_id: keeps track of the session.
        """

        self.l_maximum_bit_length = l_maximum_bit_length
        self.communicator = communicator
        self.other_party = other_party
        self.scheme_paillier = scheme_paillier
        self.scheme_dgk = scheme_dgk
        self.session_id = session_id

    async def perform_secure_comparison(
        self,
        x_enc: PaillierCiphertext,
        y_enc: PaillierCiphertext,
    ) -> PaillierCiphertext:
        """
        Performs all steps of the secure comparison protocol for Alice.
        Performs required communication with Bob.

        :param x_enc: first encrypted input variable $[[x]]$.
        :param y_enc: second encrypted input variable $[[y]]$.
        :return: Encrypted value of $(x<=y)$: $[[(x<=y)]]$.
        :raise ValueError: raised when communicator is not propertly configured.
        """
        if self.communicator is None:
            raise ValueError("Communicator not properly initialized.")

        self.session_id += 1
        session_id = self.session_id

        # make sure you have the schemes. Always receive them to make sure they are the same.
        await self.receive_encryption_schemes(session_id)

        self.scheme_paillier = cast(Paillier, self.scheme_paillier)
        self.scheme_dgk = cast(DGK, self.scheme_dgk)

        # step 1
        z_enc, r_plain = Initiator.step_1(
            x_enc, y_enc, self.l_maximum_bit_length, self.scheme_paillier
        )

        z_enc.randomize()
        await self.communicator.send(
            self.other_party, z_enc, msg_id=f"step_1_session_{session_id}"
        )

        # step 3
        alpha = Initiator.step_3(r_plain, self.l_maximum_bit_length)

        d_enc, beta_is_enc = await self.communicator.recv(
            self.other_party, msg_id=f"step_4b_session_{session_id}"
        )

        # step 4c
        d_enc = Initiator.step_4c(d_enc, r_plain, self.scheme_dgk, self.scheme_paillier)

        # step 4d
        alpha_is_xor_beta_is_enc = Initiator.step_4d(alpha, beta_is_enc)

        # step 4e
        w_is_enc_step4e, alpha_tilde = Initiator.step_4e(
            r_plain, alpha, alpha_is_xor_beta_is_enc, d_enc, self.scheme_paillier
        )

        # step 4f
        w_is_enc = Initiator.step_4f(w_is_enc_step4e)

        # step 4g
        s_plain, delta_a = Initiator.step_4g()

        # step 4h
        c_is_enc_step4h = Initiator.step_4h(
            s_plain,
            alpha,
            alpha_tilde,
            d_enc,
            beta_is_enc,
            w_is_enc,
            delta_a,
            self.scheme_dgk,
        )

        # step 4i
        c_is_enc = Initiator.step_4i(c_is_enc_step4h, self.scheme_dgk, do_shuffle=True)

        for c in c_is_enc:
            c.randomize()
        await self.communicator.send(
            self.other_party, c_is_enc, msg_id=f"step_4i_session_{session_id}"
        )
        zeta_1_enc, zeta_2_enc, delta_b_enc = await self.communicator.recv(
            self.other_party, msg_id=f"step_5_session_{session_id}"
        )

        # step 6
        beta_lt_alpha_enc = Initiator.step_6(delta_a, delta_b_enc)

        # step 7
        x_leq_y_enc = Initiator.step_7(
            zeta_1_enc,
            zeta_2_enc,
            r_plain,
            self.l_maximum_bit_length,
            beta_lt_alpha_enc,
            self.scheme_paillier,
        )

        return x_leq_y_enc

    async def receive_encryption_schemes(self, session_id: int = 1) -> None:
        """
        Receives encryption schemes Paillier and DGK (without secret keys) from Bob.

        :param session_id: distinguish communication different sessions.
        :raise ValueError: raised when communicator is not properly configured.
        """
        if self.communicator is None:
            raise ValueError("Communicator not properly initialized.")

        self.scheme_paillier, self.scheme_dgk = await self.communicator.recv(
            self.other_party, msg_id=f"schemes_session_{session_id}"
        )

    @staticmethod
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

    @staticmethod
    def step_1(
        x_enc: PaillierCiphertext,
        y_enc: PaillierCiphertext,
        l: int,
        scheme_paillier: Paillier,
    ) -> Tuple[PaillierCiphertext, int]:
        r"""
        $A$ chooses a random number $r, 0 \leq r < N$, and computes
        $$[[z]] \leftarrow [[y - x + 2^l + r]] = [[x]] \cdot [[y]]^{-1} \cdot [[2^l + r]]
        \mod N^2.$$

        :param x_enc: Encrypted value of $x$: $[[x]]$.
        :param y_enc: Encrypted value of $y$: $[[y]]$.
        :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x$, $y$ that will be given as
            input to this method.
        :param scheme_paillier: Paillier encryption scheme.
        :return: Tuple containing as first entry the encrypted value of $z$:
            $[[z]] \leftarrow [[y - x + 2^l + r]] = [[y]] \cdot [[x]]^{-1} \cdot [[2^l + r]] \mod
            N^2$. The second entry is the randomness value $r$.
        """
        assert (1 << (l + 2)) < scheme_paillier.public_key.n // 2
        r = randbelow(scheme_paillier.public_key.n)
        # Note: the paper has a typo here, it says x - y, i/o y - x.
        return (
            y_enc
            - x_enc
            + scheme_paillier.unsafe_encrypt((1 << l) + r, apply_encoding=False),
            r,
        )

    @staticmethod
    def step_3(r: int, l: int) -> List[int]:
        r"""
        $A$ computes $\alpha = r \mod 2^l$.

        :param r: The randomness value $r$ from step 1.
        :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will
            be given as input to this method.
        :return: Value $\alpha = r \mod 2^l$ as bits.
        """
        return to_bits(r % (1 << l), l)

    @staticmethod
    def step_4c(
        d_enc: DGKCiphertext, r: int, scheme_dgk: DGK, scheme_paillier: Paillier
    ) -> DGKCiphertext:
        r"""
        $A$ corrects $[d]$ by setting $[d] \leftarrow [0]$ whenever $0 \leq r < (N - 1)/2$.

        :param d_enc: Encrypted value of $d$: $[d]$.
        :param r: The randomness value $r$ from step 1.
        :param scheme_dgk: DGK encryption scheme.
        :param scheme_paillier: Paillier encryption scheme.
        :return: Corrected encrypted value of $d$: $[d]$. If $0 \leq r < (N - 1)/2$, then
            $[d] \leftarrow [0]$, else $[d]$ remains unaltered.
        """
        assert (
            0 <= r < scheme_paillier.public_key.n
        )  # If step 1 is used, this is no issue. But this function can also be called seperately.
        if r < (scheme_paillier.public_key.n - 1) // 2:
            d_enc = scheme_dgk.unsafe_encrypt(0, apply_encoding=False)
        return d_enc

    @staticmethod
    def step_4d(
        alpha: List[int], beta_is_enc: List[DGKCiphertext]
    ) -> List[DGKCiphertext]:
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

        def compute_xor(alpha_i: int, beta_i_enc: DGKCiphertext) -> DGKCiphertext:
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

    @staticmethod
    def step_4e(
        r: int,
        alpha: List[int],
        alpha_is_xor_beta_is_enc: List[DGKCiphertext],
        d_enc: DGKCiphertext,
        scheme_paillier: Paillier,
    ) -> Tuple[List[DGKCiphertext], List[int]]:
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
        :param scheme_paillier: Paillier encryption scheme.
        :return: Tuple containing as first entry a list containing the encrypted values of the bits
            $w_i$: $[w_i], 0 \leq i < l$.
            The second entry is the value $\tilde{\alpha} = (r - N) \mod 2^l$ as bits.
        """
        l = len(alpha_is_xor_beta_is_enc)

        def compute_w(
            alpha_i: int, alpha_tilde_i: int, alpha_i_xor_beta_i_enc: DGKCiphertext
        ) -> DGKCiphertext:
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

        alpha_tilde = to_bits(int((r - scheme_paillier.public_key.n) % (1 << l)), l)
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

    @staticmethod
    def step_4f(w_is_enc: List[DGKCiphertext]) -> List[DGKCiphertext]:
        r"""
        For each $i, 0 \leq i < l$, $A$ computes $[w_i] \leftarrow [w_i]^{2^i} \mod n$
        such that these values will not interfere each other when added.

        :param w_is_enc: List containing the encrypted values of the bits $w_i$: $[w_i],
            0 \leq i < l$.
        :return: List containing the encrypted values of the bits $w_i$: $[w_i], 0 \leq i < l$.
        """
        base = 1

        def compute_w(w_i_enc: DGKCiphertext) -> DGKCiphertext:
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

    @staticmethod
    def step_4g() -> Tuple[int, int]:
        r"""
        $A$ chooses a uniformly random bit $\delta_A$ and computes $s = 1 - 2 \cdot \delta_A$.

        :return: Tuple containing as first entry the value $s = 1 - 2 \cdot \delta_A$.
            The second entry is the value $\delta_A$.
        """
        delta_a = randbelow(2)
        return 1 - 2 * delta_a, delta_a

    @staticmethod
    def step_4h(
        s: int,
        alpha: List[int],
        alpha_tilde: List[int],
        d_enc: DGKCiphertext,
        beta_is_enc: List[DGKCiphertext],
        w_is_enc: List[DGKCiphertext],
        delta_a: int,
        scheme_dgk: DGK,
    ) -> List[DGKCiphertext]:
        r"""
        For each $i, 0 \leq i < l$, $A$ computes $[c_i] = [s] \cdot [\alpha_i] \cdot
        [d]^{\tilde{\alpha}_i-\alpha_i} \cdot [\beta_i]^{-1} \cdot
        (\Pi^{l-1}_{j=i+1}[w_j])^3 \mod n$.
        We add an additional value $[c_{-1}]$, with
        $c_{-1}=\delta_A + \Sigma^{l-1}_{i=0}(x_i \oplus y_i)$ to also make
        the scheme work in case of equality of $x$ and $y$.

        :param s: The value $s$ from step 4g.
        :param alpha: The value $\alpha$ from step 3.
        :param alpha_tilde: The value $\tilde{\alpha}$ from step 4e.
        :param d_enc: Encrypted value of $d$: $[d]$.
        :param beta_is_enc: List containing the encrypted values of the bits $\beta_i$:
            $[\beta_i], 0 \leq i < l$.
        :param w_is_enc: List containing the encrypted values of the bits $w_i$: $[w_i],
            0 \leq i < l$.
        :param delta_a: The value $\delta_A$ from step 4g.
        :param scheme_dgk: DGK encryption scheme.
        :return: List containing the encrypted values of the bits $c_i$:
            $[c_i] = [s] \cdot [\alpha_i]
            \cdot [d]^{\tilde{\alpha}_i-\alpha_i} \cdot [\beta_i]^{-1}
            \cdot (\Pi^{l-1}_{j=i+1}[w_j])^3 \mod n, 0 \leq i < l$.
        """
        l = len(beta_is_enc)

        c_is_enc = [
            scheme_dgk.unsafe_encrypt(s, apply_encoding=False) for _ in range(l)
        ]
        w_is_enc_sum: Union[int, DGKCiphertext] = 0

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
        c_is_enc.insert(0, cast(DGKCiphertext, delta_a + w_is_enc_sum))
        return c_is_enc

    @staticmethod
    def step_4i(
        c_is_enc: List[DGKCiphertext], scheme_dgk: DGK, do_shuffle: bool = True
    ) -> List[DGKCiphertext]:
        r"""
        $A$ blinds the numbers $c_i$ by raising them to a random non-zero exponent
        $r_i \in \{1,\ldots,u-1\}$.

        :param c_is_enc: List containing the encrypted values of the bits $c_i$: $[c_i],
            0 \leq i < l$.
        :param scheme_dgk: DGK encryption scheme.
        :param do_shuffle: Boolean parameter stating whether or not the bits should
            be shuffled randomly.
        :return: List containing the encrypted values of the masked bits $c_i$: $[c_i],
            0 \leq i < l$.
        """
        u = scheme_dgk.public_key.u

        def mask(c_i_enc: DGKCiphertext) -> DGKCiphertext:
            r"""
            Compute $[c_i]$.

            :param c_i_enc: Encrypted value of the bit $c_i$: $[c_i]$.
            :return: Encrypted value of the bit $c_i$: $[c_i]$.
            """
            c_i_enc *= randbelow(u - 1) + 1
            return c_i_enc

        c_is_enc_masked = list(map(mask, c_is_enc))
        return Initiator.shuffle(c_is_enc_masked) if do_shuffle else c_is_enc_masked

    @staticmethod
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

    @staticmethod
    def step_7(
        zeta_1_enc: PaillierCiphertext,
        zeta_2_enc: PaillierCiphertext,
        r: int,
        l: int,
        beta_lt_alpha_enc: PaillierCiphertext,
        scheme_paillier: Paillier,
    ) -> PaillierCiphertext:
        r"""
        $A$ computes $[[(x \leq y)]] \leftarrow
        [[\zeta]] \cdot ([[ r \div 2^l]] \cdot [[(\beta < \alpha)]])^{-1} \mod N^2$, where
        $\zeta = \zeta_1$, if $r < (N - 1) / 2$, else $\zeta = \zeta_2$.

        :param zeta_1_enc: Encrypted value of $\zeta_1$: $[[\zeta_1]]$.
        :param zeta_2_enc: Encrypted value of $\zeta_2$: $[[\zeta_2]]$.
        :param r: The randomness value $r$ from step 1.
        :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be given
            as input to this method.
        :param beta_lt_alpha_enc: Encrypted value of $(\beta < \alpha)$: $[[(\beta < \alpha)]]$.
        :param scheme_paillier: Paillier encryption scheme.
        :return: Encrypted value of $(x \leq y)$: $[[(x \leq y)]]$. This is the final result of the
            computation.
        """
        # We use the fix mentioned in the paper here, to also make this work in case of overflow
        zeta_enc = (
            zeta_1_enc if r < (scheme_paillier.public_key.n - 1) // 2 else zeta_2_enc
        )
        return zeta_enc - (
            scheme_paillier.unsafe_encrypt(r // (1 << l), apply_encoding=False)
            + beta_lt_alpha_enc
        )
