# TNO MPC Lab - Protocols - Secure Comparison

The TNO MPC lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of MPC solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed MPC functionalities to boost the development of new protocols and solutions.

The package tno.mpc.secure_comparison is part of the TNO Python Toolbox.

*Remark: This cryptography software may not be used in applications that violate international export control legislations.*

## Documentation

Documentation of the tno.mpc.secure_comparison package can be found [here](https://docs.mpc.tno.nl/protocols/secure_comparison/0.1.6).

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

The protocol currently only uses Paillier, instead of Paillier and DGK.

## Usage
```python
from tno.mpc.protocols.secure_comparison.secure_comparison import *
from tno.mpc.encryption_schemes.paillier import Paillier

if __name__ == "__main__":
    # Setup the paillier scheme
    scheme = Paillier.from_security_parameter(key_length=2048)

    # Encrypt two numbers (x,y) for the protocol and set the maximum bit_length (l)
    x = 23
    y = 42
    x_enc = scheme.encrypt(x)
    y_enc = scheme.encrypt(y)
    l = 10

    # Execute the protocol steps (Note: a real implementation still needs to take care of the
    # communication. 
    z_enc, r = step_1(x_enc, y_enc, l)
    z, beta = step_2(z_enc, l)
    alpha = step_3(r, l)
    d_enc = step_4a(z, scheme)
    beta_is_enc = step_4b(beta, l, scheme)
    d_enc = step_4c(d_enc, r)
    alpha_is_xor_beta_is_enc = step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = step_4e(r, alpha, alpha_is_xor_beta_is_enc, d_enc)
    w_is_enc = step_4f(w_is_enc)
    s, delta_a = step_4g()
    c_is_enc = step_4h(s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a)
    c_is_enc = step_4i(c_is_enc)
    c_is_enc = shuffle(c_is_enc)  # do a random shuffle of c_is_enc
    delta_b = step_4j(c_is_enc)
    zeta_1_enc, zeta_2_enc, delta_b_enc = step_5(z, l, delta_b, scheme)
    beta_lt_alpha_enc = step_6(delta_a, delta_b_enc)
    x_leq_y_enc = step_7(zeta_1_enc, zeta_2_enc, r, l, beta_lt_alpha_enc)
    x_leq_y = scheme.decrypt(x_leq_y_enc)
    assert x_leq_y == 1
```
