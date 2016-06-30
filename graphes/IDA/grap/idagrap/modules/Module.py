#!/usr/bin/env python

#
# Types definitions
#
module_groups = {
    "None": 0,                  # None
    "Crypto": 1,                # Cryptographic patterns
    "Compression": 2,           # Compression patterns
}

crypto_types = {
    "None": 0,                  # None
    "Block": 1,                 # Block cipher patterns
    "Stream": 2,                # Stream cipher patterns
    "Mode": 3,                  # Mode of operation patterns
    "Hash": 4,                  # Hash patterns
}

compression_types = {
    "None": 0,                  # None
    "Lossless": 1,              # Lossless compression patterns
    "Lossy": 2,                 # Lossy compression patterns
}

#
# Base
#


class Module:
    """Pattern module.

    This class allow the creation of a pattern module.

    Attributes:
        _name (str): Module name (eg. "RC4")
        _author (list): List of module authors (eg. ['Bender', 'Leela'])
        _description (str): Description of the module (eg.
                                                      "RC4 stream cipher.")
        _group (int): Group of pattern module (eg. Crypto, Compression).
                     All the groups are defined in the `module_groups`
                     dictionary.

    Args:
        name (str): Module name (default value: "")
        author (list): List of module authors (default value: None)
        description (str): Description of the module (default value: "")
        group (int): Group of pattern module (eg. Crypto, Compression).
                     Default value: module_groups["None"].
    """

    _name = ""
    _author = []
    _description = ""
    _group = module_groups["None"]

    def __init__(self, name="", author=None, description="", group=module_groups["None"]):
        """Initialization of the class."""
        if not author:
            author = []

        # Attributes initialization
        self._name = name
        self._author = author
        self._description = description
        self._group = group

    def __str__(self):
        """String representation of the class."""
        res = "Name: " + self._name + "\n"
        res += "Author: " + self._author.__str__() + "\n"
        res += "Description: " + self._description + "\n"
        res += "Group: " + self.get_group_str() + "\n"


        return res

    def get_name(self):
        """Name getter.

        Returns:
            The return value is the `_name` attribute.
        """
        return self._name

    def get_author(self):
        """Author getter.

        Returns:
            The return value is the `_author` attribute.
        """
        return self._author

    def get_description(self):
        """Description getter.

        Returns:
            The return value is the `_description` attribute.
        """
        return self._description

    def get_group_str(self):
        """Get the group name.

        Returns:
            The return value is the string representation of the
            `_group` attribute.
        """
        for key, value in module_groups.iteritems():
            if self._group == value:
                return key

        return ""
#
# Crypto
#


class ModuleCrypto(Module):
    """Cryptographic pattern module.

    This class handle all cryptographic patterns.

    Attributes:
        _type (int): Type of the crypto group (eg. 'Stream', 'Block', ...). All
                     types are defined in the `crypto_types` dictionary.

    Args:
        name (str): Module name (default value: "")
        author (list): List of module authors (default value: None)
        description (str): Description of the module (default value: "")
        c_type (int): Crypto type of the group (default value:
                      crypto_types["None"])

    """

    _type = crypto_types["None"]

    def __init__(self, name="", author=None, description="", c_type=crypto_types["None"]):
        """Initialization of the class."""
        # Attributes initialization
        Module.__init__(self, name, author, description, module_groups["Crypto"])
        self._type = c_type

    def __str__(self):
        """String representation of the class."""
        res = Module.__str__(self)
        res += "Type: " + self.get_type_str() + "\n"

        return res

    def get_type_str(self):
        """Get the group name.

        Returns:
            The return value is the string representation of the
            `_type` attribute.
        """
        for key, value in crypto_types.iteritems():
            if self._type == value:
                return key

        return ""


class ModuleCryptoStream(ModuleCrypto):
    """Stream cipher pattern module.

    This class handle all stream cipher patterns.

    Attributes:
        _patterns (Patterns list): List of Patterns

    Args:
        patterns (Patterns list): List of Patterns (default value: None).
        name (str): Module name (default value: "").
        author (list): List of module authors (default value: None).
        description (str): Description of the module (default value: "").
    """

    _patterns = []

    def __init__(self, patterns=None, name="", author=None, description=""):
        """Initialization of the class."""
        if not patterns:
            patterns = []

        # Attributes initialization
        ModuleCrypto.__init__(self, name, author, description, crypto_types["Stream"])
        self._patterns = patterns

    def __str__(self):
        """String representation of the class."""
        res = "{\n"
        res += ModuleCrypto.__str__(self)
        for patterns in self._patterns:
            res += patterns.__str__()
        res += "}\n"

        return res

    def get_patterns(self):
        """Patterns getter.

        Returns:
            The return value is the `_patterns` attribute which is a list
            of Patterns.
        """
        return self._patterns

#
# Compression
#


class ModuleCompression(Module):
    """Compression pattern module.

    This class handle all compression patterns.

    Attributes:
        _type (int): Type of the compression group (eg. 'Lossless' or 'Lossy').
                     All types are defined in the `compression_types`
                     dictionary.

    Args:
        name (str): Module name (default value: "")
        author (list): List of module authors (default value: [])
        description (str): Description of the module (default value: "")
        c_type (int): Compression type of the group (default value:
                      compression_types["None"])
    """

    _type = compression_types["None"]

    def __init__(self, name="", author=None, description="", c_type=compression_types["None"]):
        """Initialization of the class."""
        # Attributes initialization
        Module.__init__(self, name, author,
                        description, module_groups["Compression"])
        self._type = c_type
