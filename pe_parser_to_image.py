import matplotlib.pyplot as plt
from hex_parser import HexParser
# from pe_parser.hexadecimal_parser import HexParser

hex_parser = HexParser("./executable_files/PING.EXE")
hex_values = hex_parser.extract_hex_values()
# hex_values = hex_parser.extract_hex_values()
# int_values = hex_parser.convert_hex_values_to_int(preprocess=False,hex_values=hex_values)
# structural_entropy = hex_parser.extract_structural_entropy(hex_values=int_values, chunk_size=256)