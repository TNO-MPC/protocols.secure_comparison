""" Functions that don't belong to one of the players"""

from typing import List


def to_bits(integer: int, bit_length: int) -> List[int]:
    """
    Convert a given integer to a list of bits, with the least significant bit first, and the most
    significant bit last.

    :param integer: Integer to be converted to bits.
    :param bit_length: Amount of bits to which the integer should be converted.
    :return: Bit representation of the integer in bit_length bits. Least significant bit first,
        most significant last.
    """
    assert integer < (1 << bit_length)
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
