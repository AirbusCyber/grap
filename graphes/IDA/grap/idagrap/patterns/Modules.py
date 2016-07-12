#!/usr/bin/env python

from .compression.ModulesCompression import COMPRESSION
from .cryptography.ModulesCrypto import CRYPTO

MODULES = {
    "Crypto": CRYPTO,
    "Compression": COMPRESSION,
}
