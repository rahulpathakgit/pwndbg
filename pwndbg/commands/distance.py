#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pwndbg.arch
import pwndbg.commands
import pwndbg.hexdump
import pwndbg.memory
import pwndbg.regs


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def distance(a, b):
    a = int(a) & pwndbg.arch.ptrmask
    b = int(b) & pwndbg.arch.ptrmask

    a,b = sorted((a,b))

    words = (b-a) // pwndbg.arch.ptrsize

    msg = [
    '%#x -> %#x' % (a,b),
    '%#x bytes,' % (b-a),
    '%#x words' % ((b-a)//pwndbg.arch.ptrsize)
    ]

    remainder = (b-a) % pwndbg.arch.ptrsize
    if remainder:
        msg += ['(plus %i bytes)' % (remainder)]

    print(' '.join(msg))
