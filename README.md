# TNO MPC Lab - Protocols - Secure Comparison

The TNO MPC lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of MPC solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed MPC functionalities to boost the development of new protocols and solutions.

The package tno.mpc.secure_comparison is part of the TNO Python Toolbox.

*Remark: This cryptography software may not be used in applications that violate international export control legislations.*  
*This implementation of cryptographic software has not been audited. Use at your own risk.*

## Documentation

Documentation of the tno.mpc.secure_comparison package can be found [here](https://docs.mpc.tno.nl/protocols/secure_comparison/4.1.2).

## Install

Easily install the tno.mpc.secure_comparison package using pip:
```console
$ python -m pip install tno.mpc.secure_comparison
```

## Note:
A significant performance improvement for some algorithms can be achieved by installing the GMPY2 library.
```console
$ python -m pip install tno.mpc.secure_comparison[gmpy]
```

## Usage
```python
import asyncio

from tno.mpc.communication import Pool
from tno.mpc.encryption_schemes.dgk import DGK
from tno.mpc.encryption_schemes.paillier import Paillier
from tno.mpc.encryption_schemes.utils import next_prime

from tno.mpc.protocols.secure_comparison import Initiator, KeyHolder


async def run_protocol():
    taskA = asyncio.create_task(alice.perform_secure_comparison(x_enc, y_enc))
    taskB = asyncio.create_task(bob.perform_secure_comparison())

    x_leq_y_enc, _ = await asyncio.gather(*[taskA, taskB])
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert x_leq_y == 1


if __name__ == "__main__":
    # Set maximum bit length
    l = 16
    # Setup the Paillier scheme
    scheme_paillier = Paillier.from_security_parameter(key_length=2048)
    # Setup the DGK scheme
    u = next_prime((1 << (l + 2)))
    scheme_dgk = DGK.from_security_parameter(
        v_bits=160, n_bits=2048, u=u, full_decryption=False
    )

    # Setup communication pools
    pool_alice = Pool()
    pool_alice.add_http_server(8040)
    pool_alice.add_http_client("keyholder", "localhost", 8041)
    pool_bob = Pool()
    pool_bob.add_http_server(8041)
    pool_bob.add_http_client("initiator", "localhost", 8040)

    # Encrypt two numbers (x,y) for the protocol and set the maximum bit_length (l)
    x = 23
    y = 42
    x_enc = scheme_paillier.encrypt(x)
    y_enc = scheme_paillier.encrypt(y)

    alice = Initiator(l, communicator=pool_alice, other_party="keyholder")
    bob = KeyHolder(
        l,
        communicator=pool_bob,
        other_party="initiator",
        scheme_paillier=scheme_paillier,
        scheme_dgk=scheme_dgk,
    )

    # Run entire protocol interactively:
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_protocol())

    # Or execute the protocol steps without interaction
    z_enc, r = alice.step_1(x_enc, y_enc, l, scheme_paillier)
    z, beta = bob.step_2(z_enc, l, scheme_paillier)
    alpha = alice.step_3(r, l)
    d_enc = bob.step_4a(z, scheme_dgk, scheme_paillier, l)
    beta_is_enc = bob.step_4b(beta, l, scheme_dgk)
    d_enc = alice.step_4c(d_enc, r, scheme_dgk, scheme_paillier)
    alpha_is_xor_beta_is_enc = alice.step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = alice.step_4e(
        r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme_paillier
    )
    w_is_enc = alice.step_4f(w_is_enc)
    s, delta_a = alice.step_4g()
    c_is_enc = alice.step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, scheme_dgk
    )
    c_is_enc = alice.step_4i(c_is_enc, scheme_dgk)
    delta_b = bob.step_4j(c_is_enc, scheme_dgk)
    zeta_1_enc, zeta_2_enc, delta_b_enc = bob.step_5(z, l, delta_b, scheme_paillier)
    beta_lt_alpha_enc = alice.step_6(delta_a, delta_b_enc)
    x_leq_y_enc = alice.step_7(
        zeta_1_enc, zeta_2_enc, r, l, beta_lt_alpha_enc, scheme_paillier
    )
    x_leq_y = scheme_paillier.decrypt(x_leq_y_enc)
    assert x_leq_y == 1
```

The communicator object is required only when the protocol is ran through `perform_secure_comparison`. In that case, one may choose to pass any communicator object that adheres to the `tno.mpc.protocols.secure_comparison.Communicator` protocol. An example can be found in the unit tests.

### ! SAFETY NOTICE ! ENSURE CIPHERTEXTS ARE RANDOMIZED

Since version 2.0.0 of `tno.mpc.encryption_schemes.paillier` and `tno.mpc.encryption_schemes.dgk`, it is possible to (potentially) make protocols more efficient by delaying randomization of ciphertexts. This library always operates in this 'expert' mode and therefore several protocol steps yield non-randomized ciphertext outputs. As a consequence, if the user chooses to perform the secure comparison steps manually, she needs to make sure that the resulting ciphertexts are randomized before they are communicated. If the `tno.mpc.communication` library is used (or more specifically, the Paillier and DGK serialize methods), then this will be done automatically for you (but warnings might be raised).
