## Tenet(Crypto)

## Resources


## Write-up
From the python code, we could observe that a string(the flag) is encrypted using double AES(mode=ctr) and being printed which should be the ciphertext provided in the question
I first look up how does AES(CTR mode) works, it seems that we need key + counter(initial value) to decrypt the ciphertext
Luckly we were given the counter plus we can see that the key is a hex constructed with 13 leading 0s and a 3 byte random hex
the to brute force one key it only takes maximum 16*16*16 times and should be possible
But the problem is that the flag is double encrypted, for every key we compute. 
My first attempt is to construct all posibility of another key which is (16*16*16) the total combination is 16^6 (^ = power) which should take quite some time.

But this seems to take too long to compute...
Then I came accross this term Meet in the middle attack about aes and remind me of the hint of this question
With meet in the middle attack, we can reduce the time complexity of bruteforcing the key from O(n^2) (let n be 16*16*16) to O(nlgn)(sort) or O(n)(hashing) which significantly reduce the computation needed
But for a man in the middle attack, we need both the plain text and ciphertext to find the key.
Luckyly we knew that the plaintext should have a prefix of 'hkcert20{' which allow us to use MiM attack. We could use this as our plaintext and encrypt it for every possible key(16*16*16) to contruct a lookup table
Then use another seperated loop to bruteforce key2(16*16*16) and decrypt the ciphertext with it, for each decrypted text check if there is a ecrypted prefix have the same first 18 byte. (generally constant time)
We could find both key by that
Just decrypt the ciphertext with both keys and we will get the flag:
