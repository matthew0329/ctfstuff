from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

#ciphertext is .hex()ed need undo it 
ciphertext = '6255c24aa3dd8f58c5fcb41feb90f90e73e870db651d5a963498f062c2c1572430098acf05'
ciphertext = binascii.unhexlify(ciphertext)
combination = 16**6
keyPrefix = b'\0' * 13
flagPrefix = b'hkcert20{' 
lookup = {}
key0 = 'not found'
key1 = 'not found'


#create a lookup dictionary to store all encrypted prefix with corresponding key
for i in range(0, combination):
	key = keyPrefix + i.to_bytes(3, 'big')
	aes128 = AES.new(key=key, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
	encryptedPrefix = aes128.encrypt(flagPrefix).hex()
	lookup[encryptedPrefix] = i

print("dictionary built")

#bruteforce the second key
for i in range(0, combination):
	key = keyPrefix + i.to_bytes(3, 'big')
	aes128 = AES.new(key=key, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=129))
	decryptedCipher = aes128.decrypt(ciphertext).hex()[:18]
	index = lookup.get(decryptedCipher, -1)
	if index != -1:
		print('key found')
		key0 = keyPrefix + index.to_bytes(3, 'big')
		key1 = key
		break

print(key0)
print(key1)

aes128_0 = AES.new(key=key0, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
aes128_1 = AES.new(key=key1, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=129))
print(aes128_0.decrypt(aes128_1.decrypt(ciphertext)).decode('UTF-8'))