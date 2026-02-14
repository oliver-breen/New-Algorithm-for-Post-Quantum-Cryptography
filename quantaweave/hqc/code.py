"""
Concatenated code (Reed-Solomon + Reed-Muller) for HQC.
"""

from typing import List

from .parameters import HQCParameters
from .reed_solomon import reed_solomon_encode, reed_solomon_decode
from .reed_muller import reed_muller_encode, reed_muller_decode


def code_encode(params: HQCParameters, m: List[int]) -> List[int]:
    tmp = reed_solomon_encode(params, m)
    return reed_muller_encode(params, tmp)


def code_decode(params: HQCParameters, em: List[int]) -> List[int]:
    tmp = reed_muller_decode(params, em)
    return reed_solomon_decode(params, tmp)
