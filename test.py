from collections import OrderedDict

def decimal_to_binary(decimal, length):
    """Convert decimal to binary and fill with leading zeros."""
    binary_str = bin(decimal)[2:]
    # print(binary_str,length,decimal)
    return binary_str.zfill(length)

def dict_to_binary(protocol_dict):
    """Convert protocol dictionary to binary string."""
    binary_str = ''
    for key, value in protocol_dict.items():
        print(key, value)
        if isinstance(value, list):
            length, decimal_value = value
            binary_str += decimal_to_binary(decimal_value, length)
        elif isinstance(value, dict):
            binary_str += dict_to_binary(value)
    return binary_str

def binary_to_hex(binary_string):
    hex_str = ""
    for i in range(0, len(binary_string), 4):
        chunk = binary_string[i:i+4]
        hex_str += hex(int(chunk, 2))[2:]

    print(hex_str)

protocol_dict = OrderedDict([
    ('code', [8, 6]),
    ('len_code', [8, 253]),
    ('length', [16, 32]),
    ('name_tlv_code', [8, 8]),
    ('name_tlv_length', [8, 12]),
    ('name_component_0', OrderedDict([
        ('code', [8, 8]),
        ('length', [8, 4]),
        ('value', [32, 202271770])
    ])),
    ('name_component_1', OrderedDict([
        ('code', [8, 8]),
        ('length', [8, 4]),
        ('value', [32, 202271789])
    ])),
    ('metainfo_tlv_code', [8, 30]),
    ('metainfo_tlv_length', [8, 0]),
    ('content_type_tlv', OrderedDict([
        ('code', [8, 24]),
        ('length', [8, 2]),
        ('value', [16, 0])
    ])),
    ('freshness_period_tlv', OrderedDict([
        ('code', [8, 25]),
        ('length', [8, 2]),
        ('value', [16, 0])
    ])),
    ('final_block_id_tlv', OrderedDict([
        ('code', [8, 27]),
        ('length', [8, 2]),
        ('value', [16, 0])
    ])),
    ('content_tlv_code', [8, 26]),
    ('content_tlv_length', [8, 2]),
    ('content_tlv_value', [16, 2048])
])

binary = dict_to_binary(protocol_dict)
print(binary)
hex_list = []
for i in range(0, len(binary), 32):
    binary_chunk = binary[i:i+32]
    hex_value = hex(int(binary_chunk, 2))
    hex_list.append(hex_value)

print(",".join(hex_list))