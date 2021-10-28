from pwn import *

r = Process("Rootkit.exe")
r.interactive()