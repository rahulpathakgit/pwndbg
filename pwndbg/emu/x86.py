# from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
# import unicorn.x86_const

# import pwndbg.arch
# import pwndbg.regs
# import pwndbg.emu.emulator

# prefix = 'UC_X86_REG_'

# class Emulator(pwndbg.emu.emulator.Emulator):
#     def __init__(self, pc, **registers):

#       super(Emulator, self).__init__(Uc(UC_ARCH_X86, UC_MODE_32))

#       registers = pwndbg.regs.current

#       names = registers.gpr \
#             + registers.frame \
#             + registers.stack \
#             + registers.flags \
#             + registers.pc

#       self.registers = {}

#       for name in names:



#       self.memory = {}

#     @staticmethod
#     def until_jump(self, pc=None):
#         """
#         Emulates instructions starting at the specified address until the
#         program counter is set to an address which does not linearly follow
#         the previously-emulated instruction.
#         """

#     @staticmethod
#     def until_syscall(self, pc=None):
#         """
#         Emulates instructions starting at the specified address until the program
#         counter points at a syscall instruction (int 0x80, svc, etc.).
#         """

