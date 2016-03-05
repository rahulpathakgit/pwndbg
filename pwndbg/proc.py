#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Provides values which would be available from /proc which
are not fulfilled by other modules.
"""
import functools
import psutil
import sys
from types import ModuleType

import gdb
import pwndbg.memoize


class module(ModuleType):
    @property
    def pid(self):

        # Unfortunately, gdb is wrong when connected to a remote
        # process and it's running qemu and the PID is greater than
        # 65535.
        if self.is_remote:
            for pconn in psutil.Process().connections():
                for sconn in psutil.net_connections():
                    if pconn.laddr == sconn.raddr:
                        return sconn.pid

        i = gdb.selected_inferior()
        if i is not None:
            return i.pid
        return 0

    @property
    def alive(self):
        return gdb.selected_thread() is not None

    @property
    def exe(self):
        auxv = pwndbg.auxv.get()

    def OnlyWhenRunning(self, func):
        @functools.wraps(func)
        def wrapper(*a, **kw):
            if self.alive:
                return func(*a, **kw)
        return wrapper

    @property
    def is_remote(self):
        return 'Remote' in gdb.execute('info file',to_string=True,from_tty=False)

# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, '')
