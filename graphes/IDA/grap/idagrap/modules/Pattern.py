#!/usr/bin/env python

from idagrap.config.General import MAX_THRESHOLD


class Pattern:
    r"""Pattern class.

    This class is a representation of a pattern.

    Attributes:
        _file (str): File path (eg. "C:\test.dot").

    Args:
        f (str): File path (default value: "").
    """

    _file = ""

    def __init__(self, f=""):
        """Initialization of the class."""
        self._file = f

    def __str__(self):
        """String representation of the class."""
        res = ""
        res += "File: " + self._file + "\n"

        return res

    def get_file(self):
        """File getter.

        Returns:
            The return value is the `_file` attribute.
        """
        return self._file


class Patterns():
    """Patterns class.

    This class is a representation of multiple patterns.

    Attributes:
        _patterns (Pattern list): List of patterns (default value: []).
        _threshold (float): Threshold of the module. Its value can vary between
                            0 and 1 (see MIN_THRESHOLD and MAX_THRESHOLD).
                            The threshold value is compared to the
                            number_of_function_patterns divided by the
                            number_of_detected_function_patterns 
                            (default value: MAX_THRESHOLD).
        _size (int): Size of `_patterns`.

    Args:
        threshold (float): Threshold of the module (default value: 1.0).
    """

    _patterns = []
    _threshold = MAX_THRESHOLD
    _size = 0

    def __init__(self, patterns=None, threshold=MAX_THRESHOLD):
        """Initialization of the class."""
        if not patterns:
            patterns = []

        self._patterns = patterns
        self._threshold = threshold
        self._size = len(patterns)

    def __str__(self):
        """String representation of the class."""
        res = ""
        for pattern in self._patterns:
            res += pattern.__str__()
        res += "Threshold: " + self._threshold.__str__() + "\n"
        res += "Size: " + self._size.__str__() + "\n"

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
