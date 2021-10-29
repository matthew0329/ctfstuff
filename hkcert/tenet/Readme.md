## Tenet(Crypto)

## Resources
```
Future people bring us time inversion and quantum computers. Try to decrypt the ciphertext to get the flag.
```
```
Ciphertext: 6255c24aa3dd8f58c5fcb41feb90f90e73e870db651d5a963498f062c2c1572430098acf05
```
```
hint: Tips: In "Tenet", red team and blue team meet in the middle.
```
enc.py file

## Write-up
From the python code, we could observe that a string(the flag) is encrypted using double AES(mode=ctr) and being printed which should be the ciphertext provided in the question
I first look up how does AES(CTR mode) works, it seems that we need key + counter(initial value) to decrypt the ciphertext

![Ctr_encryption](https://user-images.githubusercontent.com/49106442/139240651-8fb14006-aee4-4b34-982b-7b99bb557992.png)

Luckly we were given the counter plus we can see that the key is a hex constructed with 13 leading 0s and a 3 random byte (each byte have 2 hex digit which have 16^2=256 combinations) i.e. much better than 128bit
```python
#counter given
self.aes128_0 = AES.new(key=key0, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
self.aes128_1 = AES.new(key=key1, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=129))
#key 16 byte and must have 13 leading 0s
key1 = b'\0' * 13 + os.urandom(3)
key2 = b'\0' * 13 + os.urandom(3)
```
To brute force one key it only takes maximum 16^6 times which should be possible
But the flag is double encrypted. 
My first attempt is to construct all posibility of another key(16^6) for each of (16^6)key1 the total combination is 16^12 which should take quite some time.
But this seems to take too long to compute...

Then I came accross this term meet-in-the-middle attack about realted to AES n DES and remind me of the hint of this question
https://en.wikipedia.org/wiki/Meet-in-the-middle_attack
With meet in the middle attack, we can reduce the time complexity of bruteforcing the key from O(n^2) (let n be 16*16*16) to O(nlgn)(sort) or O(n)(hashing) which significantly reduce the computation needed
```python
#create a lookup dictionary to store all encrypted prefix with corresponding key
combination = 256*256*256
for i in range(0, combination):
	key = keyPrefix + i.to_bytes(3, 'big')
	aes128 = AES.new(key=key, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
	encryptedPrefix = aes128.decrypt(flagPrefix).hex()
	lookup[encryptedPrefix] = i
```
But for a meet-in-the-middle attack, we need both the plain text and ciphertext to find the key.
We dont know the exact plain text, but we knew that the plaintext should have a prefix of 'hkcert20{' which allow us to use MiM attack. We could use this as our plaintext and encrypt it for every possible key(16*16*16) to contruct a lookup table

Then use another seperated loop to bruteforce key2(16*16*16) and decrypt the ciphertext with it, for each decrypted text check if there is a ecrypted prefix have the same first x byte.
We could find both key by that
```python
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

```
Just decrypt the ciphertext with both keys and we will get the flag:
```python
aes128_0 = AES.new(key=key0, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
aes128_1 = AES.new(key=key1, mode=AES.MODE_CTR, counter=Counter.new(128, initial_value=129))
print(aes128_0.decrypt(aes128_1.decrypt(ciphertext)).decode('UTF-8'))
```
## Full Code
```python
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
```
## Flag
```
key0 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00+!0'
key1 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00&\x84\xd2'
hkcert20{7h3_b361nn1n6_15_7h3_3nd1n6}
```
## Helmet
My code definitely could be optimised but its just a ctf, just make sure the time complexity for the bruteforce is reasonable and let it run for some time
