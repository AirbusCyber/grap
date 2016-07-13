#!/usr/bin/env python

from .compression.ModulesCompression import COMPRESSION
from .cryptography.ModulesCrypto import CRYPTO
from .test.ModulesTest import TEST

MODULES = {
    "Crypto": CRYPTO,
    "Compression": COMPRESSION,
    "Test": TEST
}
