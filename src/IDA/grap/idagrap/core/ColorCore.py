#!/usr/bin/env python

class ColorCore:
    @staticmethod
    def rgb_to_int(rgb):
        """Convert a rgb tuple to an int.

        Arguments:
            rgb (tuple): Rgb color.

        Returns:
            (int): The return value is an rgb color.
        """
        r = int(rgb[0] * 255) << 16
        g = int(rgb[1] * 255) << 8
        b = int(rgb[2] * 255)

        return r | g | b

    @staticmethod
    def rgb_to_bgr(rgb):
        """Convert a RGB -> BGR.

        Arguments:
            rgb (int): RGB color.

        Returns:
            (int): The return value is an BGR color.
        """
        r = (rgb & 0xFF0000) >> 16
        g = (rgb & 0xFF00)
        b = (rgb & 0xFF) << 16

        return b | g | r
