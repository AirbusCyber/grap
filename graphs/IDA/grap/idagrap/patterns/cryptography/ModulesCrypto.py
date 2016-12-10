#!/usr/bin/env python

from .block.ModulesCryptoBlock import CRYPTO_BLOCK
from .hash.ModulesCryptoHash import CRYPTO_HASH
from .mode.ModulesCryptoMode import CRYPTO_MODE
from .stream.ModulesCryptoStream import CRYPTO_STREAM

CRYPTO = {
    "Stream": CRYPTO_STREAM,
    "Block": CRYPTO_BLOCK,
    "Mode": CRYPTO_MODE,
    "Hash": CRYPTO_HASH,
}
