import pefile

def extract_pe_headers(file_path):
    pe = pefile.PE(file_path)

    # DOS Header
    dos_header = pe.DOS_HEADER.__dict__

    # DOS Stub
    dos_stub = pe.get_data(pe.DOS_HEADER.e_lfanew)

    # NT Headers
    nt_headers = {
        "Signature": pe.NT_HEADERS.Signature,
        "File_Header": pe.FILE_HEADER.__dict__,
        "Optional_Header": pe.OPTIONAL_HEADER.__dict__
    }

    # Section Headers
    section_headers = []
    for section in pe.sections:
        section_headers.append({
            "Name": section.Name.decode().strip('\x00'),
            "VirtualSize": section.Misc_VirtualSize,
            "VirtualAddress": section.VirtualAddress,
            "SizeOfRawData": section.SizeOfRawData,
            "PointerToRawData": section.PointerToRawData
        })

    pe.close()

    return {
        "DOS Header": dos_header,
        "DOS Stub": dos_stub,
        "NT Headers": nt_headers,
        "Section Headers": section_headers
    }
    
file_path = "./executable_files/notepad.exe"
headers = extract_pe_headers(file_path)

# Output extracted headers
for header, content in headers.items():
    print(f"--- {header} ---")
    if isinstance(content, dict) or isinstance(content, list):
        print(content)
    else:
        print(content[:10], '...')  # Show first 10 bytes of the DOS Stub
        
def headers_to_vector(headers, vector_size=1024):
    feature_vector = []
    
    # Convert DOS Header fields to numbers
    feature_vector += list(headers["DOS Header"].values())
    
    # Convert NT Headers (e.g., Signature, File Header)
    feature_vector.append(headers["NT Headers"]["Signature"])
    feature_vector += list(headers["NT Headers"]["File_Header"].values())
    feature_vector += list(headers["NT Headers"]["Optional_Header"].values())
    
    # Convert Section Headers (selecting a few important fields)
    for section in headers["Section Headers"]:
        feature_vector.append(section["VirtualSize"])
        feature_vector.append(section["VirtualAddress"])
        feature_vector.append(section["SizeOfRawData"])
    
    # Ensure the feature vector has exactly 1024 elements (padding/truncating)
    if len(feature_vector) >= vector_size:
        feature_vector = feature_vector[:vector_size]
    else:
        feature_vector += [0] * (vector_size - len(feature_vector))
    
    return feature_vector

headers = extract_pe_headers(file_path)
vector = headers_to_vector(headers)
print(vector)