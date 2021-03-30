"""
Implementation of secure comparison protocol as given in https://eprint.iacr.org/2018/1100.pdf.
"""

# Explicit re-export of all functionalities, such that they can be imported properly. Following
# https://www.python.org/dev/peps/pep-0484/#stub-files and
# https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
from .secure_comparison import to_bits as to_bits
from .secure_comparison import from_bits as from_bits
from .secure_comparison import shuffle as shuffle
from .secure_comparison import step_1 as step_1
from .secure_comparison import step_2 as step_2
from .secure_comparison import step_3 as step_3
from .secure_comparison import step_4a as step_4a
from .secure_comparison import step_4b as step_4b
from .secure_comparison import step_4c as step_4c
from .secure_comparison import step_4d as step_4d
from .secure_comparison import step_4e as step_4e
from .secure_comparison import step_4f as step_4f
from .secure_comparison import step_4g as step_4g
from .secure_comparison import step_4h as step_4h
from .secure_comparison import step_4i as step_4i
from .secure_comparison import step_4j as step_4j
from .secure_comparison import step_5 as step_5
from .secure_comparison import step_6 as step_6
from .secure_comparison import step_7 as step_7

__version__ = "0.1.6"
