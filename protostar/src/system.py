#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *
import os
import sys

_DEBUG = True

io = process('./system', aslr=False)

pack = make_packer()
unpack = make_unpacker()

def radare2():
    c = "aaaa; db main; "
    c += "db 0x56555539; "
    c += "db; "

    pid = util.proc.pidof(io)[0]
    os.system('screen r2 -d %d -c "%s"' % (pid, c))
    util.proc.wait_for_debugger(pid)

def exploit():
    io.interactive()

if __name__ == "__main__":
    if _DEBUG:
        radare2()
    exploit()
