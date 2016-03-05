#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import gdb
import pwndbg.commands
import pwndbg.events
import pwndbg.symbol
import pwndbg.color
import pwndbg.regs
import pwndbg.stdio

tracking = False
breakpoint = None

# Maps each address to whether or not it is allocated, free,
# or metadata.
#
# If allocated, the value is the base address.
# If free, the value is the 'free' sentinel.
free = object()
mapping = {}

class MallocFinishBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, size):
        self.size = size
        super(MallocFinishBreakpoint, self).__init__(internal=True)
    def stop(self):
        pwndbg.memoize.reset_on_stop.reset_all()
        address = pwndbg.regs.retval
        for i in range(self.size):
            mapping[address + i] = address

class MallocBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super(MallocBreakpoint, self).__init__('malloc', internal=True)
    def stop(self):
        pwndbg.memoize.reset_on_stop.reset_all()
        MallocFinishBreakpoint(pwndbg.regs.arguments[0])

class FreeFinishBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, address):
        self.address = address
        super(FreeFinishBreakpoint, self).__init__(internal=True)
    def stop(self):
        address = self.address
        while address in mapping \
        and mapping[address] == self.address:
            mapping[address] = free
            address += 1

        # If there are any allocations that follow our freed one,
        # mark all of them as 'free'.
        # For the sake of sanity, only do this up to the size of
        # a page.
        if max(mapping) > address:
            for i in range(4096):
                if address in mapping:
                    break

                mapping[address] = free
                address += 1

class FreeBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super(FreeBreakpoint, self).__init__('free', internal=True)
    def stop(self):
        pwndbg.memoize.reset_on_stop.reset_all()
        FreeFinishBreakpoint(pwndbg.regs.arguments[0])

bp_malloc = None
bp_free = None

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def malloc():
    global tracking
    global bp_malloc
    global bp_free
    tracking = not tracking

    if tracking:
        print("Heap tracking is %s" % pwndbg.color.green("ON"))
        bp_malloc = MallocBreakpoint()
        bp_free = FreeBreakpoint()
    else:
        print("Heap tracking is %s" % pwndbg.color.red("OFF"))
        bp_malloc.delete()
        bp_free.delete()

def dump_heap_entry(start, size, free):
    color = pwndbg.color.green
    msg = "%#x: %#x bytes"

    if last == free:
        color = pwndbg.color.blue
        msg += " (free)"
        last = address - size

    msg = msg % (last, size)

    print(color(msg))

    last = start
    size = 1


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def heap():
    last = None
    size = 0

    # Chunks are tuple of start, stop, free
    chunks = []

    for address in sorted(mapping):
        start = mapping[address]

        # Next byte in the same allocation
        if start == last:
            size += 1

        # First allocation
        elif last is None:
            last = start
            size = 1

        # New allocation begins
        elif last:
            is_free = last is free

            if is_free:
                last = address-size

            chunks.append((last, size, is_free))
            last = start
            size = 1

    # The last one...
    if last is not None:
        is_free = last is free

        if is_free:
            last = address-size

        chunks.append((last, size, is_free))

    for start, size, is_free in chunks:
        color = pwndbg.color.green
        msg = "%#x: %#x bytes"

        if is_free:
            color = pwndbg.color.blue
            msg += " (free)"

        msg = msg % (start, size)

        print(color(msg))


