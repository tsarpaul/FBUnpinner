import os
import sys
import shutil

from elftools.elf.sections import SymbolTableSection
from elftools.elf.elffile import ELFFile

def find_function(elf: ELFFile, func_name: str):
    """Finds function's offset from the beginning of the elf file"""
    text_section = elf.get_section_by_name(".text")
    # sh_offset is the address at which the first byte should reside
    text_section_virt_addr = text_section.header.sh_addr
    # sh_offset is the byte offset from the beginning of the file to the first byte in the section
    text_section_file_offset = text_section.header.sh_offset 

    symbol_tables = [s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)]
    if not symbol_tables:
        raise Exception("[!] ERROR: Could not find necessary symbol tables!")

    func_virt_addr = -1
    for section in symbol_tables:
        if section["sh_entsize"] == 0:
            print(f"[-] WARNING: Could not find symbol entries for symbol table {section.name}!")
            continue
        for sym in section.iter_symbols():
            if sym.name == func_name:
                if sym.entry.st_info.type != "STT_FUNC":
                    print(f"[-] WARNING: Found symbol {sym.name} but as unexpected type {sym.entry.st_info.type}!")
                func_virt_addr = sym.entry.st_value
                break
        if func_virt_addr != -1:
            break
    if func_virt_addr == -1:
        raise Exception("[!] ERROR: Could not find the function {sym.name}!")
    func_offset = func_virt_addr - text_section_virt_addr
    func_file_offset = text_section_file_offset + func_offset
    print(f"[+] Found function at address {hex(func_file_offset)}")
    return func_file_offset

def patch_file(path, offset, code):
    with open(path, "r+b") as f:
        f.seek(offset)
        bytes_written = f.write(bytearray(code))
    return bytes_written

if __name__ == "__main__":
    try:
        libcoldstart_path = sys.argv[1]
    except IndexError:
        libcoldstart_path = os.path.join(os.getcwd(), "libcoldstart.so")
    try:
        new_path = sys.argv[2]
    except IndexError:
        new_path = os.path.join(os.path.dirname(libcoldstart_path), "libcoldstart-patched.so")

    func_name = "_ZN8proxygen15SSLVerification17verifyWithMetricsEbP17x509_store_ctx_stRKSsPNS0_31SSLFailureVerificationCallbacksEPNS0_31SSLSuccessVerificationCallbacksERKNS_15TimeUtilGenericINSt6chrono3_V212steady_clockEEERNS_10TraceEventE"
    f = open(libcoldstart_path, "rb")
    elf = ELFFile(f)
    arch = elf.get_machine_arch()
    if arch != "ARM" and arch != "x86":
        print("[!] ERROR: Unknown architecture in libcoldstart.so, this script only supports ARM and x86!")
    func_file_offset = find_function(elf, func_name)
    f.close()
    if arch == "ARM":
        func_file_offset -= 1  # THUMB
        code = [0x01,0x20,0xf7,0x46]  # movs r0, #1; mov pc, lr;
    else:  # x86
        code = [0xb8,0x01,0x00,0x00,0x00,0xc3]  # mov eax, 0x1; ret;
    shutil.copyfile(libcoldstart_path, new_path)
    bytes_written = patch_file(new_path, func_file_offset, code)
    print(f"[+] {bytes_written} were overwritten!")


