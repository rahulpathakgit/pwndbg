import unicorn as U

def hook_mem_invalid(uc, access, address, size, value, user_data):
    uc.mem_map(address & ~0xfff, 0x1000)
    return True

def emulate_shellcode(sc):
    u=U.Uc(U.UC_ARCH_X86, U.UC_MODE_32)
    u.mem_map(0x10000000, 4096)
    u.mem_write(0x10000000, sc)
    u.reg_write(U.x86_const.UC_X86_REG_FS, 0xdead0000)
    u.hook_add(U.UC_HOOK_MEM_READ_UNMAPPED | U.UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
    u.emu_start(0x10000000, 0x10000000 + len(sc))


# mov eax, 0x12340000
# mov eax, dword ptr [eax]
mov_eax_eax = '\xb8\x00\x004\x12\x8b\x00'
emulate_shellcode(mov_eax_eax)


# mov eax, fs:0
mov_eax_fs = 'd\xa1\x00\x00\x00\x00'
emulate_shellcode(mov_eax_fs)
