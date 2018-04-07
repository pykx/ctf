#!/usr/bin/env python

from __future__ import print_function, division, absolute_import
from pwn import *
import sys

context.log_level = logging.DEBUG
context.binary = './pwn3'
context.terminal = 'screen'

io = process('./pwn3')

gdb.attach(io)

io.recvuntil('Now what should I echo?')

io.interactive()
