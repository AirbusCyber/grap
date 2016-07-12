#!/usr/bin/env python

from idagrap.modules.Module import ModuleCryptoStream

from .set_key.RC4SetKey import RC4_SET_KEY

CRYPTO_STREAM_RC4 = ModuleCryptoStream(
    patterns=[RC4_SET_KEY],
    name="RC4",
    author=["Jonathan Thieuleux"],
    description="RC4 Stream Cipher."
)
