import "pe"
//import "vt"

rule bootkit_disable_WP_CR0_2 {
  meta:
    author = "Binarly"
    description = "Designed to catch bootkit clearing the WP bit in CR0"
    exemplar = "MoonBounce (2d4991c3b6da35745e0d4f76dffbca56), CosmicStrand (ddfe44f87fac7daeeb1b681dea3300e9), ESPecter (de0743386904654b00f79a5e37a8c563)"

  strings:
    // "__writecr0(v1 & 0xFFFFFFFFFFFEFFFF);" or "__writecr0(v1 & 0xFFFEFFFF);"
    // 0f20c0                              mov     rax, cr0; control/debug register
    // 4825fffffeff                        and     rax, 0FFFFFFFFFFFEFFFFh
    // 0f22c0                              mov     cr0, rax; control/debug register
    $clear_wp_in_cr0 = { 0F 20 C? [1-5] ff ff fe ff 0f 22 c? }
    // FPs in edk2 (modules in OvmfPkg, UefiCpuPkg, EmulatorPkg)
    $fp_AsmCpuid = { 5?89??5?5?0fa24d85??74??4189??5?e3??89??4c89??e3??89??488b??2?38e3??89??5?5?c3 } // https://github.com/tianocore/edk2/blob/master/MdePkg/Library/BaseLib/X64/CpuId.nasm
    $fp_AsmCpuidEx = { 5?89??89??5?0fa24c8b??2?384d85??74??4189??4c89??e3??89??4c89??e3??89??488b??2?40e3??89??5?5?c3 } // https://github.com/tianocore/edk2/blob/master/MdePkg/Library/BaseLib/X64/CpuIdEx.nasm
    $fp_SevIoWriteFifo8 = { 4887??4987??e8????????85??75??fcf36eeb??e3??8a??ee48ffc?e2??4c89??c3 } // https://github.com/tianocore/edk2/blob/master/MdePkg/Library/BaseIoLibIntrinsic/X64/IoFifoSev.nasm#L185
    // bootkit-like bootloaders
    $fp_konboot = "Kon-Boot Driver loaded"
    $fp_hypersim = "Hypersim booting ..."
    
  condition:
    filesize < 8MB and pe.is_pe and pe.is_64bit() and
    (pe.subsystem == pe.SUBSYSTEM_EFI_APPLICATION or pe.subsystem == pe.SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER or
     pe.subsystem == pe.SUBSYSTEM_EFI_RUNTIME_DRIVER or pe.subsystem == pe.SUBSYSTEM_EFI_ROM_IMAGE) and
    $clear_wp_in_cr0 and none of ($fp_*)
}

rule bootkit_disable_CET_CR4 {
  meta:
    author = "Binarly"
    description = "Designed to catch bootkit clearing the CET bit in CR4"
    exemplar = "AsmDisableCet in EfiGuard (https://github.com/Mattiwatti/EfiGuard/blob/master/EfiGuardDxe/X64/Cet.asm#L9)"

  strings:
    $AsmDisableCet = { b9 a2 06 00 00 0f 32 a8 01 74 0a b8 01 00 00 00 f3 48 0f ae e8 0f 20 e0 0f ba f0 17 0f 22 e0 c3 } // hard-codeded in EfiGuard
    
  condition:
    pe.is_pe and
    (pe.subsystem == pe.SUBSYSTEM_EFI_APPLICATION or pe.subsystem == pe.SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER or
     pe.subsystem == pe.SUBSYSTEM_EFI_RUNTIME_DRIVER or pe.subsystem == pe.SUBSYSTEM_EFI_ROM_IMAGE) and
    $AsmDisableCet
}

rule bootkit_EfiGuard_signatures {
  meta:
    author = "Binarly"
    description = "Designed to catch old EfiGuard bootkit variants without AsmDisableCet"
    exemplar = "Abismo (https://github.com/TheMalwareGuardian/Abismo/blob/main/AbismoBootkitPkg/Driver/Functions/Utils/10FunctionsUtilsSignatures.h)"

  strings:
    $SigImgArchStartBootApplication = { 41 b8 09 00 00 d0 }
    $SigOslFwpKernelSetupPhase1 = { 89 cc 24 01 00 00 e8 cc cc cc cc cc 8b cc }
    $SigSeCodeIntegrityQueryInformation = { 48 83 ec cc 48 83 3d cc cc cc cc 00 4d 8b c8 4c 8b d1 74 cc }
    $SeCodeIntegrityQueryInformationPatch = { 41 c7 00 08 00 00 00 33 c0 c7 41 04 01 00 00 00 c3 }
    
  condition:
    pe.is_pe and
    (pe.subsystem == pe.SUBSYSTEM_EFI_APPLICATION or pe.subsystem == pe.SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER or
     pe.subsystem == pe.SUBSYSTEM_EFI_RUNTIME_DRIVER or pe.subsystem == pe.SUBSYSTEM_EFI_ROM_IMAGE) and
    all of them
}

rule bootkit_resolve_api_addr {
  meta:
    author = "Binarly"
    description = "Designed to catch potential bootkit samples resolving kernel API address by string hash"
    exemplar = "MoonBounce (2d4991c3b6da35745e0d4f76dffbca56), CosmicStrand (ddfe44f87fac7daeeb1b681dea3300e9), ESPecter (de0743386904654b00f79a5e37a8c563)"

  strings:
    $exp_dir = { 
                 // 8bbc3d88000000                      mov     edi, [rbp+rdi+IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress]
                 // ...
                 8b [1-2] 88 00 00 00 [0-15]
                 // 8b5720                              mov     edx, [rdi+IMAGE_EXPORT_DIRECTORY.AddressOfNames]
                 // 4801ea                              add     rdx, rbp
                 // 4831f6                              xor     rsi, rsi
                 // 8b348a                              mov     esi, [rdx+rcx*4]
                 // ... (hash calculation and check loop)
                 8b ?? 20 [0-75]
                 // 8b5f24                              mov     ebx, [rdi+IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
                 // 4801eb                              add     rbx, rbp
                 // 668b0c4b                            mov     cx, [rbx+rcx*2]
                 // 4831db                              xor     rbx, rbx
                 8b ?? 24 [0-15]
                 // 8b5f1c                              mov     ebx, [rdi+IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
                 // 4801eb                              add     rbx, rbp
                 // 4831c0                              xor     rax, rax
                 // 8b048b                              mov     eax, [rbx+rcx*4]
                 8b ?? 1c [0-15] 8b 04
               }

  condition:
    filesize < 8MB and pe.is_pe and pe.is_64bit() and
    (pe.subsystem == pe.SUBSYSTEM_EFI_APPLICATION or pe.subsystem == pe.SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER or
     pe.subsystem == pe.SUBSYSTEM_EFI_RUNTIME_DRIVER or pe.subsystem == pe.SUBSYSTEM_EFI_ROM_IMAGE) and
    all of them  
}

rule bootkit_resolve_relocation {
  meta:
    author = "Binarly"
    description = "Designed to catch potential bootkit samples resolving relocations for malicious drivers"
    exemplar = "MoonBounce (2d4991c3b6da35745e0d4f76dffbca56), BlackLotus (a9f822ac0a137584ea6a5b4fcf0cbd8b)"

  strings:
    // 8b81b0000000                        mov     eax, [rcx+0B0h]    ; baseRelocDir->VirtualAddress
    // 443991b4000000                      cmp     [rcx+0B4h], r10d    ; baseRelocDir->Size
    //$dir_access1 = { 8b??b0000000 [0-30] b4000000 }
    //$dir_access2 = { b4000000 [0-30] 8b??b0000000 }
    $dir_access1 = { 8b[1-2]b0000000 [0-30] b4000000 }
    $dir_access2 = { b4000000 [0-30] 8b[1-2]b0000000 }
    // c1e80c                              shr     eax, 0Ch    ; UINT16 type = data >> 12;
    // 83f80a                              cmp     eax, 0Ah    ; EFI_IMAGE_REL_BASED_DIR64
    $based_dir64_1 = { c1e?0c [4-12] 83f?0a }
    // be00f00000                          mov     esi, 0F000h
    // bd00a00000                          mov     ebp, 0A000h
    $based_dir64_2 = { b?00f00000 [0-8] b?00a00000 }
    // 81e1ff0f0000                        and     ecx, 0FFFh    ; UINT16 offset = data & 0xFFF;
    $rel_fix = { 81e?ff0f0000 }
    // 4883e808                            sub     rax, 8    ; UINT32 relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
    // 48d1e8                              shr     rax, 1    ;                      / sizeof(UINT16);
    // 4983ea08                            sub     r10, 8
    // 49d1ea                              shr     r10, 1
    $rel_size_of_block1 = { 4?83e?08 [0-3] 4?d1e? }
    // 83c0f8                              add     eax, 0FFFFFFF8h    ; generated by old compilers?
    // ...
    // 49d1ea                              shr     r10, 1
    $rel_size_of_block2 = { 83c?f8 [0-8] 4?d1e? }

  condition:
    filesize < 8MB and pe.is_pe and pe.is_64bit() and
    (pe.subsystem == pe.SUBSYSTEM_EFI_APPLICATION or pe.subsystem == pe.SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER or
     pe.subsystem == pe.SUBSYSTEM_EFI_RUNTIME_DRIVER or pe.subsystem == pe.SUBSYSTEM_EFI_ROM_IMAGE) and
    ($dir_access1 or $dir_access2) and ($based_dir64_1 or $based_dir64_2) and $rel_fix and ($rel_size_of_block1 or $rel_size_of_block2)
    //and vt.metadata.first_submission_date > 1388502000 // exclude old bootloaders before 2013
}

rule peibackdoor_relocation {
  meta:
    author = "Binarly"
    description = "Designed to catch potential bootkit samples running in PEI stage"
    exemplar = "LdrProcessRelocs in PeiBackdoor (https://github.com/Cr4sh/PeiBackdoor/blob/master/src/loader.c#L8)"

  strings:
    // 8b413c                              mov     eax, [rcx+3Ch]
    // ...
    // 448b80b4000000                      mov     r8d, [rax+0B4h]
    // 448b88b0000000                      mov     r9d, [rax+0B0h]
    // ...
    // 81e7ff0f0000                        and     edi, 0FFFh
    $reloc64 = { 8b??3c [0-40] 8b??b?000000 [0-20] 8b??b?000000 [0-100] 81e?ff0f0000 }
    // 8b473c                              mov     eax, [Image+3Ch]
    // ...
    // 8b88a0000000                        mov     ecx, [eax+0A0h]
    // ...
    // 8bb0a4000000                        mov     esi, [eax+0A4h]
    // ...
    // 81e1ff0f0000                        and     ecx, 0FFFh
    $reloc32 = { 8b??3c [0-40] 8b??a?000000 [0-20] 8b??a?000000 [0-100] 81e?ff0f0000 }

  condition:
    (
      (uint16(0) == 0x5A4D and (pe.subsystem == pe.SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER or pe.subsystem == pe.SUBSYSTEM_EFI_RUNTIME_DRIVER))
      or
      (uint16(0) == 0x5A56)
    ) and
    any of them
}
