import sys
import os

if (len(sys.argv)<=1):
	print("Usage: "+sys.argv[0]+" <minidump file>")
	exit(1)

# Get name of minidump file
dumpfile = sys.argv[1]

# Read in bytes from minidump
with open(dumpfile, "rb") as f:
	d = f.read()
data = bytearray(d)

# Derive XOR key by decrypting MDMP header
key = bytearray([0, 0, 0, 0])
for i in range(4):
	for b in range(256):
		headerByte = (data[i] ^ b)
		if (i == 0 and headerByte == ord('M')):
			key[0] = b
			#print("[DEBUG] FOUND FIRST KEY BYTE: " + str(b))
		if (i == 1 and headerByte == ord('D')):
			key[1] = b
			#print("[DEBUG] FOUND SECOND KEY BYTE: " + str(b))
		if (i == 2 and headerByte == ord('M')):
			key[2] = b
			#print("[DEBUG] FOUND THIRD KEY BYTE: " + str(b))
		if (i == 3 and headerByte == ord('P')):
			key[3] = b
			#print("[DEBUG] FOUND FOURTH KEY BYTE: " + str(b))
print("[+] Detected XOR key: " + str(key))

# XOR decrypt each byte in the file
print("[*] Decrypting minidump file...")
i = 0
while i < len(data):
	# Decrypt minidump with 4-byte key
	for j in range(4):
		data[i] = (data[i] ^ key[j])
		i = i + 1
		# Exit loop early if at end of file
		if (i >= len(data)):
			j = 4
			break

# Write decoded bytes to '<filename>_decoded.dmp'
dumpfile = (dumpfile + "_decrypted.dmp")
with open(dumpfile, "wb") as fwrite:
	fwrite.write(data)
print("[+] Decrypted file written to " + dumpfile)
