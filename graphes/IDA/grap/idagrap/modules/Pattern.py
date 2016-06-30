#!/usr/bin/env python

from idagrap.config.General import MAX_THRESHOLD


class Pattern:
    r"""Pattern class.

    This class is a representation of a pattern.

    Attributes:
        _file (str): File path (eg. "C:\test.dot").
        _name (str): Name of the pattern (eg. "First loop")
        _description (str): Description of the Pattern (eg.
                            "First Initialization loop of RC4 set_key.").

    Args:
        f (str): File path (default value: "").
        name (str): Name of the pattern (default value: "")
        description (str): Description of the Pattern (default value: "").
    """

    _file = ""
    _name = ""

    def __init__(self, f="", name="", description=""):
        """Initialization of the class."""
        self._file = f
        self._name = name
        self._description = description

    def __str__(self):
        """String representation of the class."""
        res = "(\n"
        res += "Name: " + self._name + "\n"
        res += "Description: " + self._description + "\n"
        res += "File: " + self._file + "\n"
        res += ")\n"
        return res

    def get_file(self):
        """File getter.

        Returns:
            The return value is the `_file` attribute.
        """
        return self._file

    def get_name(self):
        """Name getter.

        Returns:
            The return value is the `_name` attribute.
        """
        return self._name

    def get_description(self):
        """Description getter.

        Returns:
            The return value is the `_description` attribute.
        """
        return self._description


class Patterns():
    """Patterns class.

    This class is a representation of multiple patterns.

    Attributes:
        _patterns (Pattern list): List of patterns.
        _threshold (float): Threshold of the module. Its value can vary between
                            0 and 1 (see MIN_THRESHOLD and MAX_THRESHOLD).
                            The threshold value is compared to the
                            number_of_function_patterns divided by the
                            number_of_detected_function_patterns 
                            (default value: MAX_THRESHOLD).
        _size (int): Size of `_patterns`.
        _name (str): Name of the Patterns (eg. "RC4 Set_Key")
        _description (str): Description of the Patterns (eg.
                            "Initialization function of the RC4 algorithm.")

    Args:
        patterns (Pattern list): List of patterns (default value: None).
        threshold (float): Threshold of the module (default value: 1.0).
        name (str): Name of the Patterns (default value: "")
        description (str): Description of the Patterns (default value: "").
    """

    _patterns = []
    _threshold = MAX_THRESHOLD
    _size = 0
    _name = ""
    _description = ""

    def __init__(self, patterns=None, threshold=MAX_THRESHOLD, name="", description=""):
        """Initialization of the class."""
        if not patterns:
            patterns = []

        self._patterns = patterns
        self._threshold = threshold
        self._size = len(patterns)
        self._name = name
        self._description = description

    def __str__(self):
        """String representation of the class."""
        res = "[\n"
        res += "Name: " + self._name + "\n"
        res += "Description: " + self._description + "\n"

        for pattern in self._patterns:
            res += pattern.__str__()

        res += "Threshold: " + self._threshold.__str__() + "\n"
        res += "Size: " + self._size.__str__() + "\n"
        res += "]\n"

        return res

    def get_patterns(self):
        """Patterns getter.

        Returns:
            The return value is the `_pattern` attribute.
        """
        return self._patterns

    def get_threshold(self):
        """Threshold getter.

        Returns:
            The return value is the `_threshold` attribute.
        """
        return self._threshold

    def get_size(self):
        """Size getter.

        Returns:
            The return value is the `_size` attribute.
        """
        return self._size

    def get_name(self):
        """Name getter.

        Returns:
            The return value is the `_name` attribute.
        """
        return self._name

    def get_description(self):
        """Description getter.

        Returns:
            The return value is the `_description` attribute.
        """
        return self._description
