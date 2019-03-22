import os
import sys
import shutil

from elftools.elf.sections import SymbolTableSection
from elftools.elf.elffile import ELFFile


def patch_file(path, offset, code):
    with open(path, "r+b") as f:
        f.seek(offset)
        bytes_written = f.write(bytearray(code))
    return bytes_written


class FuncNotFound(Exception):
    pass


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
        raise FuncNotFound("[!] ERROR: Could not find the function {sym.name}!")
    func_offset = func_virt_addr - text_section_virt_addr
    func_file_offset = text_section_file_offset + func_offset
    print(f"[+] Found function at address {hex(func_file_offset)}")
    return func_file_offset


class ThumbUtils:
    # TODO: disassemble instructions to accommodate arbitrary number of registers pushed/popped
    fastcall_start = b"\x2d\xe9\xf0\x4f"  # PUSH.W {R4-R11,LR}
    fastcall_end = b"\xbd\xe8\xf0\x83"  # POP.W {R4-R9,LR}

    @staticmethod
    def seek_bytes(f, step, target, size):
        addr = f.seek(0, 1)  # Get current address
        while True:
            code = f.read(size)
            if code == target:
                return addr
            # Revert the read and move a step
            addr = f.seek(step - size, 1)


class TLS12Patcher:
    def __init__(self, stream, elf, arch, out_path):
        self.stream = stream
        self.elf = elf
        self.arch = arch
        self.out_path = out_path

    def patch(self):
        func_name = "_ZN8proxygen15SSLVerification17verifyWithMetricsEbP17x509_store_ctx_stRKSsPNS0_31SSLFailureVerificationCallbacksEPNS0_31SSLSuccessVerificationCallbacksERKNS_15TimeUtilGenericINSt6chrono3_V212steady_clockEEERNS_10TraceEventE"
        func_file_offset = find_function(self.elf, func_name)
        if arch == "ARM":
            func_file_offset -= 1  # THUMB
            code = [0x01, 0x20, 0xf7, 0x46]  # movs r0, #1; mov pc, lr;
        else:  # x86
            code = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]  # mov eax, 0x1; ret;
        bytes_written = patch_file(self.out_path, func_file_offset, code)
        print(f"[+] {bytes_written} bytes were overwritten!")


class TLS13Patcher:
    def __init__(self, stream, elf, arch, out_path):
        self.stream = stream
        self.elf = elf
        self.arch = arch
        self.out_path = out_path

        stream.seek(0)
        self.file_content = stream.read()

    def find_error_strings(self):
        self.verifier_str_addr = self.file_content.find("verifier failure:".encode('utf8'))
        if self.verifier_str_addr:
            return True
        return False

    def patch(self):
        """
        We bypass the defense by NOPing the certificate verifier
        """

        patch_offset = -1
        if self.arch == "ARM":            
            text_section = elf.get_section_by_name(".text")
            text_offset = text_section.header.sh_offset
            f.seek(text_offset)
            blob = f.read()

            # We look for "stable" opcodes as our signature - opcodes untouched by registers
            for i in range(len(blob)):
                # BX ADD BL LDR{Rn,0xC} CBZ
                if blob[i+1] == 0b01000111 \
                   and blob[i+3] == 0xA8 \
                   and blob[i+5] >> 3 == 0b11110 and blob[i+7] >> 3 == 0b11111 \
                   and blob[i+9] >> 4 == 0b0110 and ((blob[i+9] << 5 & 0xFF) + blob[i+8] >> 6) == 3 \
                   and blob[i+11] >> 4 == 0b1011:
                    # Unconditional Branch instead of CBZ
                    code = [blob[i+10]>>3, 0b11100000]
                    patch_offset = text_offset + i + 10
                    break

        else:  # x86
            code = b"\x90" * 22  # NOP sled
            
            text_section = elf.get_section_by_name(".text")
            text_offset = text_section.header.sh_offset
            f.seek(text_offset)
            blob = f.read()
            
            # We look for "stable" opcodes as our signature - opcodes untouched by registers
            for i in range(len(blob)):
                # jz 0x18, mov, call, mov, mov, mov, mov, call
                if blob[i:i+2] == b"\x74\x16" \
                   and blob[i+2] == 0x89 \
                   and blob[i+5] == 0xe8 \
                   and blob[i+10] == 0x8b \
                   and blob[i+12] == 0x8b \
                   and blob[i+15] == 0x89 \
                   and blob[i+19] == 0x89 \
                   and blob[i+22] == 0xff:
                        # Skip JZ
                        patch_offset = text_offset + i + 2
                        break
                        
        if patch_offset == -1:
            print("[!] Could not find the required code to patch!")
            exit(1)
        print(f"[+] Found TLS1.3 verifier at {hex(patch_offset)}")
        bytes_written = patch_file(self.out_path, patch_offset, code)
        print(f"[+] {bytes_written} bytes were overwritten!")


if __name__ == "__main__":
    # Validate command line args
    try:
        libcoldstart_path = sys.argv[1]
    except IndexError:
        libcoldstart_path = os.path.join(os.getcwd(), "libcoldstart.so")
    try:
        new_path = sys.argv[2]
    except IndexError:
        new_path = os.path.join(os.path.dirname(libcoldstart_path), "libcoldstart-patched.so")

    f = open(libcoldstart_path, "rb")
    # Validate input file
    elf = ELFFile(f)
    arch = elf.get_machine_arch()
    if arch != "ARM" and arch != "x86":
        print("[!] ERROR: Unknown architecture in libcoldstart.so, this script only supports ARM and x86!")

    shutil.copyfile(libcoldstart_path, new_path)

    patched = False
    patcher13 = TLS13Patcher(f, elf, arch, new_path)
    if patcher13.find_error_strings():
        print("[+] Patching TLS1.3 stack!")
        patcher13.patch()
        patched = True
    else:
        print("[+] Did not detect TLS1.3 stack in libcoldstart.so")

    # TODO: Try check if TLS12 stack exists
    # No harm done patching the TLS12 stack
    patcher12 = TLS12Patcher(f, elf, arch, new_path)
    try:
        patcher12.patch()
    except FuncNotFound as e:
        if patched:
            print("[!] WARNING: Failed to patch TLS1.2, but this is not critical since TLS1.3 was sucessfully patched!")
        else:
            raise

    f.close()
