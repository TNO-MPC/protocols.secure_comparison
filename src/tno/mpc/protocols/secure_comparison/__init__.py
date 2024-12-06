"""
Implementation of secure comparison protocol as given in https://eprint.iacr.org/2018/1100.pdf.
"""

# Explicit re-export of all functionalities, such that they can be imported properly. Following
# https://www.python.org/dev/peps/pep-0484/#stub-files and
# https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport

from tno.mpc.protocols.secure_comparison.communicator import (
    Communicator as Communicator,
)
from tno.mpc.protocols.secure_comparison.initiator import Initiator as Initiator
from tno.mpc.protocols.secure_comparison.keyholder import KeyHolder as KeyHolder
from tno.mpc.protocols.secure_comparison.utils import from_bits as from_bits
from tno.mpc.protocols.secure_comparison.utils import to_bits as to_bits

__version__ = "4.4.0"
