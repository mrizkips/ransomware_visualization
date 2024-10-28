import numpy as np
import pandas as pd
import pefile

pe = pefile.PE('./executable_files/notepad.exe')

def extract_to_byte_vector(d):
    byte_values = []  # List to collect all byte values

    for key, value in d.items():
        if isinstance(value, dict) and 'Value' in value:
            val = value['Value']
            if isinstance(val, str):
                # Convert string to its decimal byte values
                byte_values.extend([ord(char) for char in val])
            else:
                # If the value is greater than 255, convert it to multiple bytes
                if val > 255:
                    # Convert the integer to its byte representation (little-endian)
                    bytes_rep = val.to_bytes((val.bit_length() + 7) // 8, byteorder='little')
                    byte_values.extend(bytes_rep)
                else:
                    # If it's already 0-255, append directly
                    byte_values.append(val)
        else:
            # Skip non-dictionary values
            continue

    # Convert the list of byte values to a 1D pandas Series (vector)
    vector = pd.Series(byte_values)
    return vector

dos_header = pe.DOS_HEADER.dump_dict()
dos_header_vector = extract_to_byte_vector(dos_header)

nt_header = pe.NT_HEADERS.dump_dict()
nt_header_vector = extract_to_byte_vector(nt_header)

file_header = pe.FILE_HEADER.dump_dict()
file_header_vector = extract_to_byte_vector(file_header)

optional_header = pe.OPTIONAL_HEADER.dump_dict()
optional_header_vector = extract_to_byte_vector(optional_header)

print(pd.concat([dos_header_vector, nt_header_vector, file_header_vector, optional_header_vector], ignore_index=True))