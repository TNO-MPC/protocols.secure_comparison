import pytest

from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
from tno.mpc.protocols.secure_comparison import *

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
scheme = Paillier.from_security_parameter(key_length=1024, nr_of_threads=0)
test_vals_smaller = list(
    map(lambda value: scheme.encrypt(value), test_vals_smaller_plaintext)
)
test_vals_bigger = list(
    map(lambda value: scheme.encrypt(value), test_vals_bigger_plaintext)
)
l = 15


@pytest.mark.parametrize(
    "number", test_vals_smaller_plaintext + test_vals_bigger_plaintext
)
def test_bit_conversion(number: int):
    assert from_bits(to_bits(number, l))


@pytest.mark.parametrize(
    "x_enc, y_enc", [(x, y) for x, y in zip(test_vals_smaller, test_vals_bigger)]
)
def test_smaller_than(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext):
    z_enc, r = step_1(x_enc, y_enc, l, scheme)
    z, beta = step_2(z_enc, l, scheme)
    alpha = step_3(r, l)
    d_enc = step_4a(z, scheme)
    beta_is_enc = step_4b(beta, l, scheme)
    d_enc = step_4c(d_enc, r, scheme)
    alpha_is_xor_beta_is_enc = step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = step_4e(r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme)
    w_is_enc = step_4f(w_is_enc)
    s, delta_a = step_4g()
    c_is_enc = step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, scheme
    )
    c_is_enc = step_4i(c_is_enc, scheme)
    delta_b = step_4j(c_is_enc, scheme)
    zeta_1_enc, zeta_2_enc, delta_b_enc = step_5(z, l, delta_b, scheme)
    beta_lt_alpha_enc = step_6(delta_a, delta_b_enc)
    x_leq_y_enc = step_7(zeta_1_enc, zeta_2_enc, r, l, beta_lt_alpha_enc, scheme)
    x_leq_y = scheme.decrypt(x_leq_y_enc)
    assert x_leq_y == 1


@pytest.mark.parametrize(
    "x_enc, y_enc", [(x, y) for x, y in zip(test_vals_bigger, test_vals_smaller)]
)
def test_greater_than(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext):
    z_enc, r = step_1(x_enc, y_enc, l, scheme)
    z, beta = step_2(z_enc, l, scheme)
    alpha = step_3(r, l)
    d_enc = step_4a(z, scheme)
    beta_is_enc = step_4b(beta, l, scheme)
    d_enc = step_4c(d_enc, r, scheme)
    alpha_is_xor_beta_is_enc = step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = step_4e(r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme)
    w_is_enc = step_4f(w_is_enc)
    s, delta_a = step_4g()
    c_is_enc = step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, scheme
    )
    c_is_enc = step_4i(c_is_enc, scheme)
    delta_b = step_4j(c_is_enc, scheme)
    zeta_1_enc, zeta_2_enc, delta_b_enc = step_5(z, l, delta_b, scheme)
    beta_lt_alpha_enc = step_6(delta_a, delta_b_enc)
    x_leq_y_enc = step_7(zeta_1_enc, zeta_2_enc, r, l, beta_lt_alpha_enc, scheme)
    x_leq_y = scheme.decrypt(x_leq_y_enc)
    assert x_leq_y == 0


@pytest.mark.parametrize(
    "x_enc, y_enc", [(x, y) for x, y in zip(test_vals_bigger, test_vals_bigger)]
)
def test_equal_to(x_enc: PaillierCiphertext, y_enc: PaillierCiphertext):
    z_enc, r = step_1(x_enc, y_enc, l, scheme)
    z, beta = step_2(z_enc, l, scheme)
    alpha = step_3(r, l)
    d_enc = step_4a(z, scheme)
    beta_is_enc = step_4b(beta, l, scheme)
    d_enc = step_4c(d_enc, r, scheme)
    alpha_is_xor_beta_is_enc = step_4d(alpha, beta_is_enc)
    w_is_enc, alpha_tilde = step_4e(r, alpha, alpha_is_xor_beta_is_enc, d_enc, scheme)
    w_is_enc = step_4f(w_is_enc)
    s, delta_a = step_4g()
    c_is_enc = step_4h(
        s, alpha, alpha_tilde, d_enc, beta_is_enc, w_is_enc, delta_a, scheme
    )
    c_is_enc = step_4i(c_is_enc, scheme)
    delta_b = step_4j(c_is_enc, scheme)
    zeta_1_enc, zeta_2_enc, delta_b_enc = step_5(z, l, delta_b, scheme)
    beta_lt_alpha_enc = step_6(delta_a, delta_b_enc)
    x_leq_y_enc = step_7(zeta_1_enc, zeta_2_enc, r, l, beta_lt_alpha_enc, scheme)
    x_leq_y = scheme.decrypt(x_leq_y_enc)
    assert x_leq_y == 1


def test_stop_thread():
    scheme.randomness.shut_down()
