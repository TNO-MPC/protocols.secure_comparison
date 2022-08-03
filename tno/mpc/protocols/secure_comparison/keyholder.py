"""Party that holds the secret keys. Bob; B in the paper."""

from typing import List, Optional, Tuple, cast

from tno.mpc.encryption_schemes.dgk import DGK, DGKCiphertext
from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
from tno.mpc.encryption_schemes.utils import next_prime

from .communicator import Communicator
from .utils import to_bits


class KeyHolder:
    """
    Player Bob in the secure comparison protocol, holds the keys.
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
        :param communicator: object for handling communication with the Initiator during the protocol.
        :param other_party: identifier of the other party
        :param scheme_paillier: Paillier encryption scheme (including secret key)
            used to produce $[[x]]$ and $[[y]]$, Alice's input.
        :param scheme_dgk: DGK encryption scheme (including secret key).
        :param session_id: keeps track of the session.
        """

        self.l_maximum_bit_length = l_maximum_bit_length
        self.communicator = communicator
        self.other_party = other_party
        self.scheme_paillier = scheme_paillier
        self.scheme_dgk = scheme_dgk
        self.session_id = session_id

    async def perform_secure_comparison(self) -> None:
        """
        Performs the secure comparison secure comparison for Bob.
        Including required communication with Alice.

        :raise ValueError: raised when communicator is not properly configured.
        """
        if self.communicator is None:
            raise ValueError("Communicator not properly initialized.")

        self.session_id += 1
        session_id = self.session_id

        # make sure you have the schemes and share the public keys
        await self.make_and_send_encryption_schemes(session_id)

        self.scheme_paillier = cast(Paillier, self.scheme_paillier)
        self.scheme_dgk = cast(DGK, self.scheme_dgk)
        z_enc = await self.communicator.recv(
            self.other_party, msg_id=f"step_1_session_{session_id}"
        )

        # step 2
        z_plain, beta = KeyHolder.step_2(
            z_enc, self.l_maximum_bit_length, self.scheme_paillier
        )

        # step 4a
        d_enc = KeyHolder.step_4a(
            z_plain, self.scheme_dgk, self.scheme_paillier, self.l_maximum_bit_length
        )

        # step 4b
        beta_is_enc = KeyHolder.step_4b(
            beta, self.l_maximum_bit_length, self.scheme_dgk
        )

        d_enc.randomize()
        for b in beta_is_enc:
            b.randomize()
        await self.communicator.send(
            self.other_party,
            (d_enc, beta_is_enc),
            msg_id=f"step_4b_session_{session_id}",
        )
        c_is_enc = await self.communicator.recv(
            self.other_party, msg_id=f"step_4i_session_{session_id}"
        )

        # step 4j
        delta_b = KeyHolder.step_4j(c_is_enc, self.scheme_dgk)

        # step 5
        zeta_1_enc, zeta_2_enc, delta_b_enc = KeyHolder.step_5(
            z_plain, self.l_maximum_bit_length, delta_b, self.scheme_paillier
        )

        zeta_1_enc.randomize()
        zeta_2_enc.randomize()
        delta_b_enc.randomize()
        await self.communicator.send(
            self.other_party,
            (zeta_1_enc, zeta_2_enc, delta_b_enc),
            msg_id=f"step_5_session_{session_id}",
        )

    async def make_and_send_encryption_schemes(
        self,
        session_id: int = 1,
        key_length_paillier: int = 2048,
        v_bits_dgk: int = 160,
        n_bits_dgk: int = 2048,
    ) -> None:
        """
        Initialize Paillier and DGK encryption schemes if they don't
        already exist and sends public keys to Alice.

        :param session_id: integer to distinguish between session
        :param key_length_paillier: key length paillier
        :param v_bits_dgk: number of bits DGK private keys $v_p$ and $v_q$
        :param n_bits_dgk: number of bits DGK public key $n$
        :raise ValueError: raised when communicator is not propertly configured.
        """
        if self.communicator is None:
            raise ValueError("Communicator not properly initialized.")

        if not self.scheme_paillier:
            self.scheme_paillier = Paillier.from_security_parameter(
                key_length=key_length_paillier
            )

        if not self.scheme_dgk:
            self.scheme_dgk = DGK.from_security_parameter(
                v_bits=v_bits_dgk,
                n_bits=n_bits_dgk,
                u=next_prime((1 << (self.l_maximum_bit_length + 2))),
                full_decryption=False,
            )

        scheme_paillier_initiator = Paillier(
            public_key=self.scheme_paillier.public_key, secret_key=None
        )
        scheme_dgk_initiator = DGK(
            public_key=self.scheme_dgk.public_key, secret_key=None
        )

        await self.communicator.send(
            self.other_party,
            (scheme_paillier_initiator, scheme_dgk_initiator),
            msg_id=f"schemes_session_{session_id}",
        )

    @staticmethod
    def step_2(
        z_enc: PaillierCiphertext, l: int, scheme_paillier: Paillier
    ) -> Tuple[int, int]:
        r"""
        $B$ decrypts $[[z]]$, and computes $\beta = z \mod 2^l$.

        :param z_enc: Encrypted value of $z$: $[[z]]$.
        :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be
            given as input to this method.
        :param scheme_paillier: Paillier encryption scheme.
        :return: Tuple containing as first entry the plaintext value of $z$.
            The second entry is the value $\beta = z \mod 2^l$.
        """
        z = cast(int, scheme_paillier.decrypt(z_enc, apply_encoding=False))
        return z, z % (1 << l)

    @staticmethod
    def step_4a(
        z: int, scheme_dgk: DGK, scheme_paillier: Paillier, l: int
    ) -> DGKCiphertext:
        r"""
        $B$ computes the encrypted bit $[d]$ where $d = (z < (N - 1)/2)$ is the bit informing $A$
        whether a carryover has occurred.

        :param z: Plaintext value of $z$.
        :param scheme_dgk: DGK encryption scheme.
        :param scheme_paillier: Paillier encryption scheme.
        :return: Encrypted value of the bit $d = (z < (N - 1)/2)$: $[d]$.
        """
        assert scheme_dgk.public_key.u > (1 << (l + 2))
        return scheme_dgk.unsafe_encrypt(
            int(z < (scheme_paillier.public_key.n - 1) // 2),
            apply_encoding=False,
        )

    @staticmethod
    def step_4b(beta: int, l: int, scheme_dgk: DGK) -> List[DGKCiphertext]:
        r"""
        $B$ computes the encrypted bits $[\beta_i], 0 \leq i < l$ to $A$.

        :param beta: The value $\beta$ from step 2.
        :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be
            given as input to this method.
        :param scheme_dgk: DGK encryption scheme.
        :return: List containing the encrypted values of the bits $\beta_i$: $[\beta_i],
            0 \leq i < l$ to $A$.
        """
        return [
            scheme_dgk.unsafe_encrypt(bit, apply_encoding=False)
            for bit in to_bits(beta, l)
        ]

    @staticmethod
    def step_4j(c_is_enc: List[DGKCiphertext], scheme_dgk: DGK) -> int:
        r"""
        $B$ checks whether one of the numbers $c_i$ is decrypted to zero. If he finds one,
        $\delta_B \leftarrow 1$, else $\delta_B \leftarrow 0$.

        :param c_is_enc: List containing the encrypted values of the bits $c_i$: $[c_i],
            0 \leq i < l$.
        :param scheme_dgk: DGK encryption scheme.
        :return: Value $\delta_B$.
        """
        return int(
            any(
                map(
                    scheme_dgk.is_zero,
                    c_is_enc,
                )
            )
        )

    @staticmethod
    def step_5(
        z: int, l: int, delta_b: int, scheme_paillier: Paillier
    ) -> Tuple[PaillierCiphertext, PaillierCiphertext, PaillierCiphertext]:
        r"""
        $B$ computes $\zeta_1 = z \div 2^l$ and encrypts it to $[[\zeta_1]]$ and computes
        $\zeta_2 = (z + N) \div 2^l$ and encrypts it to $[[\zeta_2]]$. $B$ also encrypts
        $\delta_B$ to $[[\delta_B]]$.

        :param z: Plaintext value of $z$.
        :param l: Fixed value, such that $0 \leq x,y < 2^l$, for any $x, y$ that will be
            given as input to this method.
        :param delta_b: The value $\delta_B$ from step 4j.
        :param scheme_paillier: Paillier encryption scheme.
        :return: A tuple with the first entry being the encrypted value of $\zeta_1$: $[[\zeta_1]]$.
            The second entry is the encrypted value of $\zeta_2$: $[[\zeta_2]]$.
            The third entry is the encrypted value of $\delta_B$: $[[\delta_B]]$.
        """
        # We use the fix mentioned in the paper here, to also make this work in case of overflow
        zeta_1_enc = scheme_paillier.unsafe_encrypt(z // (1 << l), apply_encoding=False)
        zeta_2_enc = (
            scheme_paillier.unsafe_encrypt(
                (z + scheme_paillier.public_key.n) // (1 << l),
                apply_encoding=False,
            )
            if z < (scheme_paillier.public_key.n - 1) // 2
            else scheme_paillier.unsafe_encrypt(z // (1 << l), apply_encoding=False)
        )
        return (
            zeta_1_enc,
            zeta_2_enc,
            scheme_paillier.unsafe_encrypt(delta_b, apply_encoding=False),
        )
