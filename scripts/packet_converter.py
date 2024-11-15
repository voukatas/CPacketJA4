original_packet = (
    "005056feb6ce000c298c687f08004500022d5ca9400040068593c0a885812275edef"
    "8e1401bb237f7168310423125018faf058ae00001603010200010001fc0303ecb269"
    "1addb2bf6c599c7aaae23de5f42561cc04eb41029acc6fc050a16ac1d22046f8617b"
    "580ac9358e2aa44e306d52466bcc989c87c8ca64309f5faf50ba7b4d002213011303"
    "1302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f003501000191"
    "00000021001f00001c636f6e74696c652e73657276696365732e6d6f7a696c6c612e"
    "636f6d00170000ff01000100000a000e000c001d00170018001901000101000b0002"
    "0100002300000010000e000c02683208687474702f312e3100050005010000000000"
    "22000a000804030503060302030033006b0069001d00208909858fbeb6ed2f1248ba"
    "5b9e2978bead0e840110192c61daed0096798b184400170041044d183d91f5eed357"
    "91fa982464e3b0214aaa5f5d1b78616d9b9fbebc22d11f535b2f94c686143136aa79"
    "5e6e5a875d6c08064ad5b76d44caad766e2483012748002b00050403040303000d00"
    "18001604030503060308040805080604010501060102030201002d00020101001c00"
    "0240010015007a000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000"
)

packet_bytes = [f"0x{original_packet[i:i+2]}" for i in range(0, len(original_packet), 2)]

print("const u_char full_packet_tls12[] = {")
print(", ".join(packet_bytes) + " };")
