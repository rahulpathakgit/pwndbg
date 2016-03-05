#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Information about whether the debuggee is local (under GDB) or remote
(under GDBSERVER or QEMU stub).
"""
import gdb
import pwndbg.proc

def is_remote():
    return pwndbg.proc.is_remote
