import os
import numpy as np
import binascii

class HexParser:
    def __init__(self, hex_filepath: str):
        if not os.path.isfile(hex_filepath):
            raise IOError
        
        self.hex_filepath = hex_filepath
        
        # Processed values
        self.hex_values = None
        self.int_values = None
        
    def extract_hex_values(self) -> list:
        hex_values = []
        with open(self.hex_filepath, "rb") as hex_file:
            #Extract hex values
            for line in hex_file.readlines():
                line_values = line.split()
                # line_hexvalues = binascii.hexlify(line_values)
                # if len(line_values) != 17:
                #     continue
                # hex_values.extend(hex_value for hex_value in line_values[1:])
        # self.hex_values = hex_values
        # return hex_values
        