# ruff: noqa: E501

import dataclasses
import enum
import hashlib
import pefile
from typing import Literal, cast

# Reexports for convenience:
from pefile import PE as RawPE, PEFormatError as PEFormatError

class CoffFileMachineType(enum.IntEnum):

    IMAGE_FILE_MACHINE_UNKNOWN     = 0x0
    """ The content of this [file] is assumed to be applicable to any machine type """

    IMAGE_FILE_MACHINE_ALPHA       = 0x184
    """ Alpha AXP, 32-bit address space """

    IMAGE_FILE_MACHINE_ALPHA64     = 0x284
    """ Alpha 64, 64-bit address space """

    IMAGE_FILE_MACHINE_AM33        = 0x1d3
    """ Matsushita AM33 """

    IMAGE_FILE_MACHINE_AMD64       = 0x8664
    """ x64 """

    IMAGE_FILE_MACHINE_ARM         = 0x1c0
    """ ARM little endian """

    IMAGE_FILE_MACHINE_ARM64       = 0xaa64
    """ ARM64 little endian """

    IMAGE_FILE_MACHINE_ARM64EC     = 0xA641
    """ ABI that enables interoperability between native ARM64 and emulated x64 code. """

    IMAGE_FILE_MACHINE_ARM64X      = 0xA64E
    """ Binary format that allows both native ARM64 and ARM64EC code to coexist in the same file. """

    IMAGE_FILE_MACHINE_ARMNT       = 0x1c4
    """ ARM Thumb-2 little endian """

    IMAGE_FILE_MACHINE_AXP64       = 0x284
    """ AXP 64 (Same as Alpha 64) """

    IMAGE_FILE_MACHINE_EBC         = 0xebc
    """ EFI byte code """

    IMAGE_FILE_MACHINE_I386        = 0x14c
    """ Intel 386 or later processors and compatible processors """

    IMAGE_FILE_MACHINE_IA64        = 0x200
    """ Intel Itanium processor family """

    IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232
    """ LoongArch 32-bit processor family """

    IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264
    """ LoongArch 64-bit processor family """

    IMAGE_FILE_MACHINE_M32R        = 0x9041
    """ Mitsubishi M32R little endian """

    IMAGE_FILE_MACHINE_MIPS16      = 0x266
    """ MIPS16 """

    IMAGE_FILE_MACHINE_MIPSFPU     = 0x366
    """ MIPS with FPU """

    IMAGE_FILE_MACHINE_MIPSFPU16   = 0x466
    """ MIPS16 with FPU """

    IMAGE_FILE_MACHINE_POWERPC     = 0x1f0
    """ Power PC little endian """

    IMAGE_FILE_MACHINE_POWERPCFP   = 0x1f1
    """ Power PC with floating point support """

    IMAGE_FILE_MACHINE_R3000BE     = 0x160
    """ MIPS I compatible 32-bit big endian """

    IMAGE_FILE_MACHINE_R3000       = 0x162
    """ MIPS I compatible 32-bit little endian """

    IMAGE_FILE_MACHINE_R4000       = 0x166
    """ MIPS III compatible 64-bit little endian """

    IMAGE_FILE_MACHINE_R10000      = 0x168
    """ MIPS IV compatible 64-bit little endian """

    IMAGE_FILE_MACHINE_RISCV32     = 0x5032
    """ RISC-V 32-bit address space """

    IMAGE_FILE_MACHINE_RISCV64     = 0x5064
    """ RISC-V 64-bit address space """

    IMAGE_FILE_MACHINE_RISCV128    = 0x5128
    """ RISC-V 128-bit address space """

    IMAGE_FILE_MACHINE_SH3         = 0x1a2
    """ Hitachi SH3 """

    IMAGE_FILE_MACHINE_SH3DSP      = 0x1a3
    """ Hitachi SH3 DSP """

    IMAGE_FILE_MACHINE_SH4         = 0x1a6
    """ Hitachi SH4 """

    IMAGE_FILE_MACHINE_SH5         = 0x1a8
    """ Hitachi SH5 """

    IMAGE_FILE_MACHINE_THUMB       = 0x1c2
    """ Thumb """

    IMAGE_FILE_MACHINE_WCEMIPSV2   = 0x169
    """ MIPS little-endian WCE v2 """

class CoffFileCharacteristics(enum.IntFlag):

    IMAGE_FILE_RELOCS_STRIPPED           = 0x0001
    """ Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files. """

    IMAGE_FILE_EXECUTABLE_IMAGE          = 0x0002
    """ Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error. """

    IMAGE_FILE_LINE_NUMS_STRIPPED        = 0x0004
    """ COFF line numbers have been removed. This flag is deprecated and should be zero. """

    IMAGE_FILE_LOCAL_SYMS_STRIPPED       = 0x0008
    """ COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero. """

    IMAGE_FILE_AGGRESSIVE_WS_TRIM        = 0x0010
    """ Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero. """

    IMAGE_FILE_LARGE_ADDRESS_AWARE       = 0x0020
    """ Application can handle > 2-GB addresses. """

    _IMAGE_FILE_CHARACTERISTICS_RESERVED = 0x0040
    """ This flag is reserved for future use. """

    IMAGE_FILE_BYTES_REVERSED_LO         = 0x0080
    """ Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero. """

    IMAGE_FILE_32BIT_MACHINE             = 0x0100
    """ Machine is based on a 32-bit-word architecture. """

    IMAGE_FILE_DEBUG_STRIPPED            = 0x0200
    """ Debugging information is removed from the image file. """

    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   = 0x0400
    """ If the image is on removable media, fully load it and copy it to the swap file. """

    IMAGE_FILE_NET_RUN_FROM_SWAP         = 0x0800
    """ If the image is on network media, fully load it and copy it to the swap file. """

    IMAGE_FILE_SYSTEM                    = 0x1000
    """ The image file is a system file, not a user program. """

    IMAGE_FILE_DLL                       = 0x2000
    """ The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run. """

    IMAGE_FILE_UP_SYSTEM_ONLY            = 0x4000
    """ The file should be run only on a uniprocessor machine. """

    IMAGE_FILE_BYTES_REVERSED_HI         = 0x8000
    """ Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero. """

@dataclasses.dataclass
class DOSStub:
    """ A parsed DOS stub; only the `e_lfanew` field is parsed currently. """

    e_lfanew: int
    """ The file offset where the PE header (incl. "PE\\0\\0" magic) starts. """

@dataclasses.dataclass
class COFFFileHeader:

    Machine: CoffFileMachineType
    """ The number that identifies the type of target machine. """

    NumberOfSections: int
    """ The number of sections. This indicates the size of the section table, which immediately follows the headers. """

    TimeDateStamp: int
    """ The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), which indicates when the file was created. """

    PointerToSymbolTable: int
    """ The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated. """

    NumberOfSymbols: int
    """ The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated. """

    SizeOfOptionalHeader: int
    """ The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. """

    Characteristics: CoffFileCharacteristics
    """ The flags that indicate the attributes of the file. """

class OptionalHeaderPEMagic(enum.IntEnum):

    OPTIONAL_HEADER_MAGIC_ROM  = 0x107

    OPTIONAL_HEADER_MAGIC_PE32 = 0x10b
    """ The file is a PE32. """

    OPTIONAL_HEADER_MAGIC_PE64 = 0x20b
    """ The file is a PE32+. """

class WindowsSubsystem(enum.IntEnum):

    IMAGE_SUBSYSTEM_UNKNOWN                  = 0
    """ An unknown subsystem """

    IMAGE_SUBSYSTEM_NATIVE                   = 1
    """ Device drivers and native Windows processes """

    IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2
    """ The Windows graphical user interface (GUI) subsystem """

    IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3
    """ The Windows character subsystem """

    IMAGE_SUBSYSTEM_OS2_CUI                  = 5
    """ The OS/2 character subsystem """

    IMAGE_SUBSYSTEM_POSIX_CUI                = 7
    """ The Posix character subsystem """

    IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8
    """ Native Win9x driver """

    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9
    """ Windows CE """

    IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10
    """ An Extensible Firmware Interface (EFI) application """

    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11
    """ An EFI driver with boot services """

    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12
    """ An EFI driver with run-time services """

    IMAGE_SUBSYSTEM_EFI_ROM                  = 13
    """ An EFI ROM image """

    IMAGE_SUBSYSTEM_XBOX                     = 14
    """ XBOX """

    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
    """ Windows boot application """

class DLLCharacteristics(enum.IntFlag):

    _IMAGE_DLLCHARACTERISTICS_RESERVED_1           = 0x0001
    """ Reserved, must be zero. """

    _IMAGE_DLLCHARACTERISTICS_RESERVED_2           = 0x0002
    """ Reserved, must be zero. """

    _IMAGE_DLLCHARACTERISTICS_RESERVED_4           = 0x0004
    """ Reserved, must be zero. """

    _IMAGE_DLLCHARACTERISTICS_RESERVED_8           = 0x0008
    """ Reserved, must be zero. """

    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       = 0x0020
    """ Image can handle a high entropy 64-bit virtual address space. """

    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          = 0x0040
    """ DLL can be relocated at load time. """

    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       = 0x0080
    """ Code Integrity checks are enforced. """

    IMAGE_DLLCHARACTERISTICS_NX_COMPAT             = 0x0100
    """ Image is NX compatible. """

    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          = 0x0200
    """ Isolation aware, but do not isolate the image. """

    IMAGE_DLLCHARACTERISTICS_NO_SEH                = 0x0400
    """ Does not use structured exception (SE) handling. No SE handler may be called in this image. """

    IMAGE_DLLCHARACTERISTICS_NO_BIND               = 0x0800
    """ Do not bind the image. """

    IMAGE_DLLCHARACTERISTICS_APPCONTAINER          = 0x1000
    """ Image must execute in an AppContainer. """

    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            = 0x2000
    """ A WDM driver. """

    IMAGE_DLLCHARACTERISTICS_GUARD_CF              = 0x4000
    """ Image supports Control Flow Guard. """

    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
    """ Terminal Server aware. """

@dataclasses.dataclass
class COFFOptionalHeader:
    """ A parsed optional header. Currently, data directories are not parsed. """

    Magic: Literal[
        OptionalHeaderPEMagic.OPTIONAL_HEADER_MAGIC_ROM,
        OptionalHeaderPEMagic.OPTIONAL_HEADER_MAGIC_PE32,
        OptionalHeaderPEMagic.OPTIONAL_HEADER_MAGIC_PE64
    ]
    """ The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable. """

    MajorLinkerVersion: int
    """ The linker major version number. """

    MinorLinkerVersion: int
    """ The linker minor version number. """

    SizeOfCode: int
    """ The size of the code (text) section, or the sum of all code sections if there are multiple sections. """

    SizeOfInitializedData: int
    """ The size of the initialized data section, or the sum of all such sections if there are multiple data sections. """

    SizeOfUninitializedData: int
    """ The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections. """

    AddressOfEntryPoint: int
    """ The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero. """

    BaseOfCode: int
    """ The address that is relative to the image base of the beginning-of-code section when it is loaded into memory. """

    BaseOfData: int | None
    """
    PE32 contains this additional field, which is absent in PE32+, following BaseOfCode.

    The address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
    """

    # Windows-specific Optional header fields

    ImageBase: int
    """ The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000. """

    SectionAlignment: int
    """ The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture. """

    FileAlignment: int
    """ The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment. """

    MajorOperatingSystemVersion: int
    """ The major version number of the required operating system. """

    MinorOperatingSystemVersion: int
    """ The minor version number of the required operating system. """

    MajorImageVersion: int
    """ The major version number of the image. """

    MinorImageVersion: int
    """ The minor version number of the image. """

    MajorSubsystemVersion: int
    """ The major version number of the subsystem. """

    MinorSubsystemVersion: int
    """ The minor version number of the subsystem. """

    Win32VersionValue: int
    """ Reserved, must be zero. """

    SizeOfImage: int
    """ The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment. """

    SizeOfHeaders: int
    """ The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment. """

    CheckSum: int
    """ The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process. """

    Subsystem: WindowsSubsystem
    """ The subsystem that is required to run this image. For more information, see Windows Subsystem. """

    DllCharacteristics: DLLCharacteristics
    """ For more information, see DLL Characteristics later in this specification. """

    SizeOfStackReserve: int
    """ The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached. """

    SizeOfStackCommit: int
    """ The size of the stack to commit. """

    SizeOfHeapReserve: int
    """ The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached. """

    SizeOfHeapCommit: int
    """ The size of the local heap space to commit. """

    LoaderFlags: int
    """ Reserved, must be zero. """

    NumberOfRvaAndSizes: int
    """ The number of data-directory entries in the remainder of the optional header. Each describes a location and size. """

class PESectionCharacteristics(enum.IntFlag):

    _IMAGE_SCN_RESERVED_NULL         = 0x00000000
    """ Reserved for future use. """

    _IMAGE_SCN_RESERVED_1            = 0x00000001
    """ Reserved for future use. """

    _IMAGE_SCN_RESERVED_2            = 0x00000002
    """ Reserved for future use. """

    _IMAGE_SCN_RESERVED_4            = 0x00000004
    """ Reserved for future use. """

    IMAGE_SCN_TYPE_NO_PAD            = 0x00000008
    """ The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files. """

    _IMAGE_SCN_RESERVED_10           = 0x00000010
    """ Reserved for future use. """

    IMAGE_SCN_CNT_CODE               = 0x00000020
    """ The section contains executable code. """

    IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
    """ The section contains initialized data. """

    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    """ The section contains uninitialized data. """

    IMAGE_SCN_LNK_OTHER              = 0x00000100
    """ Reserved for future use. """

    IMAGE_SCN_LNK_INFO               = 0x00000200
    """ The section contains comments or other information. The .drectve section has this type. This is valid for object files only. """

    _IMAGE_SCN_RESERVED_400          = 0x00000400
    """ Reserved for future use. """

    IMAGE_SCN_LNK_REMOVE             = 0x00000800
    """ The section will not become part of the image. This is valid only for object files. """

    IMAGE_SCN_LNK_COMDAT             = 0x00001000
    """ The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files. """

    IMAGE_SCN_GPREL                  = 0x00008000
    """ The section contains data referenced through the global pointer (GP). """

    IMAGE_SCN_MEM_PURGEABLE          = 0x00020000
    """ Reserved for future use. """

    IMAGE_SCN_MEM_16BIT              = 0x00020000
    """ Reserved for future use. """

    IMAGE_SCN_MEM_LOCKED             = 0x00040000
    """ Reserved for future use. """

    IMAGE_SCN_MEM_PRELOAD            = 0x00080000
    """ Reserved for future use. """

    IMAGE_SCN_ALIGN_1BYTES           = 0x00100000
    """ Align data on a 1-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_2BYTES           = 0x00200000
    """ Align data on a 2-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_4BYTES           = 0x00300000
    """ Align data on a 4-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_8BYTES           = 0x00400000
    """ Align data on an 8-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
    """ Align data on a 16-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_32BYTES          = 0x00600000
    """ Align data on a 32-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_64BYTES          = 0x00700000
    """ Align data on a 64-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_128BYTES         = 0x00800000
    """ Align data on a 128-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_256BYTES         = 0x00900000
    """ Align data on a 256-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000
    """ Align data on a 512-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_1024BYTES        = 0x00B00000
    """ Align data on a 1024-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_2048BYTES        = 0x00C00000
    """ Align data on a 2048-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_4096BYTES        = 0x00D00000
    """ Align data on a 4096-byte boundary. Valid only for object files. """

    IMAGE_SCN_ALIGN_8192BYTES        = 0x00E00000
    """ Align data on an 8192-byte boundary. Valid only for object files. """

    IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000
    """ The section contains extended relocations. """

    IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
    """ The section can be discarded as needed. """

    IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
    """ The section cannot be cached. """

    IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
    """ The section is not pageable. """

    IMAGE_SCN_MEM_SHARED             = 0x10000000
    """ The section can be shared in memory. """

    IMAGE_SCN_MEM_EXECUTE            = 0x20000000
    """ The section can be executed as code. """

    IMAGE_SCN_MEM_READ               = 0x40000000
    """ The section can be read. """

    IMAGE_SCN_MEM_WRITE              = 0x80000000
    """ The section can be written to. """

@dataclasses.dataclass
class PESection:
    """ Representation of a PE section. """

    Name: str
    """
    A parsed (decoded) string representing the section name.
    Executable images do not support section names longer than 8 characters.
    Long names in object files are truncated if they are emitted to an executable file.
    """

    VirtualSize: int
    """
    The total size of the section when loaded into memory.
    If this value is greater than SizeOfRawData, the section is zero-padded.
    This field is valid only for executable images and should be set to zero for object files.
    """

    VirtualAddress: int
    """
    For executable images, the address of the first byte of the section
    relative to the image base when the section is loaded into memory.
    For object files, this field is the address of the first byte before relocation is applied;
    for simplicity, compilers should set this to zero.
    Otherwise, it is an arbitrary value that is subtracted from offsets during relocation.
    """

    SizeOfRawData: int
    """
    The size of the section (for object files) or the size of the initialized data on disk (for image files).
    For executable images, this must be a multiple of FileAlignment from the optional header.
    If this is less than VirtualSize, the remainder of the section is zero-filled.
    Because the SizeOfRawData field is rounded but the VirtualSize field is not,
    it is possible for SizeOfRawData to be greater than VirtualSize as well.
    When a section contains only uninitialized data, this field should be zero.
    """

    PointerToRawData: int
    """
    The file pointer to the first page of the section within the COFF file.
    For executable images, this must be a multiple of FileAlignment from the optional header.
    For object files, the value should be aligned on a 4-byte boundary for best performance.
    When a section contains only uninitialized data, this field should be zero.
    """

    PointerToRelocations: int
    """
    The file pointer to the beginning of relocation entries for the section.
    This is set to zero for executable images or if there are no relocations.
    """

    PointerToLinenumbers: int
    """
    The file pointer to the beginning of line-number entries for the section.
    This is set to zero if there are no COFF line numbers.
    This value should be zero for an image because COFF debugging information is deprecated.
    """

    NumberOfRelocations: int
    """
    The number of relocation entries for the section.
    This is set to zero for executable images.
    """

    NumberOfLinenumbers: int
    """
    The number of line-number entries for the section.
    This value should be zero for an image because COFF debugging information is deprecated.
    """

    Characteristics: PESectionCharacteristics
    """
    The flags that describe the characteristics of the section.
    """

    _pefile_structure: pefile.SectionStructure

    def raw_pefile_sectionstructure(self) -> pefile.SectionStructure:
        """ Returns the underlying `pefile.SectionStructure`. """
        return self._pefile_structure

    def has_characteristics(self, flags: PESectionCharacteristics) -> bool:
        """ Tests the section Characteristics for all `flags`. Returns True iff all `flags` are set. """
        return (self.Characteristics & flags) == flags

    def get_PointerToRawData_adj(self) -> int | None:
        return cast(int | None, self._pefile_structure.get_PointerToRawData_adj())

    def get_VirtualAddress_adj(self) -> int | None:
        return cast(int | None, self._pefile_structure.get_VirtualAddress_adj())

    def contains_offset(self, offset: int) -> bool:
        """ Checks whether the section contains the provided file offset. """
        return cast(bool, self._pefile_structure.contains_offset(offset))

    def contains_rva(self, rva: int) -> bool:
        """ Checks whether the section contains the provided relative virtual address (RVA). """
        return cast(bool, self._pefile_structure.contains_rva(rva))

    def get_rva_from_offset(self, offset: int) -> int:
        """ Converts a file offset to a relative virtual address (RVA), without performing bound checks. """
        return cast(int, self._pefile_structure.get_rva_from_offset(offset))

    def get_offset_from_rva(self, rva: int) -> int:
        """ Converts a relative virtual address (RVA) to a file offset, without performing bound checks. """
        return cast(int, self._pefile_structure.get_offset_from_rva(rva))

    def get_data(self, start: int | None = None, length: int | None = None, ignore_padding: bool = False) -> bytes:
        """
        Reads a chunk of raw data from the PE file's on-disk representation of the section, without performing bound checks.

        Args:
            start (int or None):
                The virtual address (VA) of the first byte to read, i.e.
                `ImageBase + RVA`, as the address would appear at runtime if the
                image were loaded at its **preferred base**. Must fall within this
                section's virtual address range. If `None`, reading begins at
                the very start of the section's raw data on disk.

            length (int or None):
                Number of bytes to read. If `None`, the read extends to the end
                of the section's raw data on disk (`SizeOfRawData` bytes from
                the computed start offset). If `SizeOfRawData` is also `None`,
                an empty bytes object is returned.

            ignore_padding (bool):
                If `True`, the result is truncated to at most `Misc_VirtualSize`
                bytes from the computed start offset, stripping any on-disk
                padding that would not be mapped into memory. This is relevant
                when `SizeOfRawData > Misc_VirtualSize`: the extra bytes on disk
                are alignment padding that the OS loader zero-fills rather than
                mapping from the file. Defaults to `False`.

        Returns:
            bytes: The requested data. May be shorter than `length` if the read
            would extend past the end of the section's raw data on disk (the
            result is silently clamped to `PointerToRawData + SizeOfRawData`).
            Returns an empty bytes object if the section has no raw data.

        Example:
            Read the first 16 bytes of the .text section at its load address
            ```
            data = section.get_data(start=va, length=16)
            ```

            Read the entire section, excluding on-disk padding
            ```
            data = section.get_data(ignore_padding=True)
            ```
        """
        return bytes(self._pefile_structure.get_data(start, length, ignore_padding))

    def get_entropy(self) -> float:
        """ Calculate and return the entropy for the section. """
        return float(self._pefile_structure.get_entropy())

    def get_hash_sha1(self) -> str:
        """ Get the SHA-1 hex-digest of the section's data. """
        return hashlib.sha1(self.get_data()).hexdigest()

    def get_hash_sha256(self) -> str:
        """ Get the SHA-256 hex-digest of the section's data. """
        return hashlib.sha256(self.get_data()).hexdigest()

    def get_hash_sha512(self) -> str:
        """ Get the SHA-512 hex-digest of the section's data. """
        return hashlib.sha512(self.get_data()).hexdigest()

    def get_hash_md5(self) -> str:
        """ Get the MD5 hex-digest of the section's data. """
        return hashlib.md5(self.get_data()).hexdigest()

@dataclasses.dataclass
class PEHeaders:
    """ Parsed representation of all PE file headers. """

    MzHeader: DOSStub
    """ Parsed DOS stub. """

    FileHeader: COFFFileHeader
    """ Parsed COFF file header. """

    OptionalHeader: COFFOptionalHeader
    """ Parsed COFF optional header. """

    Sections: list[PESection]
    """ Parsed section table. """

@dataclasses.dataclass
class Import:
    """ Parsed PE import entry. """

    DllName: str

    Symbol: str | int

@dataclasses.dataclass
class Export:
    """ Parsed PE export entry. """

    Ordinal: int

    Name: str

    Rva: int

class PE:

    def __init__(
        self,
        path: str | None = None,
        data: bytes | None = None,
        fast_load: bool | None = None,
        max_symbol_exports: int = pefile.MAX_SYMBOL_EXPORT_COUNT,
        max_repeated_symbol: int = 120,
    ) -> None:
        """
        :param: :path: Path to the PE file to load.
        :param: :data: Contents of a read PE file to parse directly (instead of opening `path`).
        :param: :fast_load: When `True`, do not parse data directories or check for truncation/malformation.
        :param: :max_symbol_exports: The maximum number of export directory entries for a file to be considered non-corrupt.
        :param: :max_repeated_symbol: The maximum number of duplicate export directory entries for a file to be considered non-corrupt.

        :raises: :PEFormatError: The file is not a valid PE file or is malformed.
        """
        self._pe = RawPE(
            name = path,
            data = data,
            fast_load = fast_load,
            max_symbol_exports = max_symbol_exports,
            max_repeated_symbol = max_repeated_symbol
        )
        self._populate_typed_structures()

    def _populate_typed_structures(self) -> None:
        MzHeader = DOSStub(
            e_lfanew = self._pe.DOS_HEADER.e_lfanew,
        )
        FileHeader = COFFFileHeader(
            Machine              = CoffFileMachineType(self._pe.FILE_HEADER.Machine),
            NumberOfSections     = self._pe.FILE_HEADER.NumberOfSections,
            TimeDateStamp        = self._pe.FILE_HEADER.TimeDateStamp,
            PointerToSymbolTable = self._pe.FILE_HEADER.PointerToSymbolTable,
            NumberOfSymbols      = self._pe.FILE_HEADER.NumberOfSymbols,
            SizeOfOptionalHeader = self._pe.FILE_HEADER.SizeOfOptionalHeader,
            Characteristics      = CoffFileCharacteristics(self._pe.FILE_HEADER.Characteristics),
        )
        OptionalHeader = COFFOptionalHeader(
            Magic                       = self._pe.OPTIONAL_HEADER.Magic,
            MajorLinkerVersion          = self._pe.OPTIONAL_HEADER.MajorLinkerVersion,
            MinorLinkerVersion          = self._pe.OPTIONAL_HEADER.MinorLinkerVersion,
            SizeOfCode                  = self._pe.OPTIONAL_HEADER.SizeOfCode,
            SizeOfInitializedData       = self._pe.OPTIONAL_HEADER.SizeOfInitializedData,
            SizeOfUninitializedData     = self._pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            AddressOfEntryPoint         = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            BaseOfCode                  = self._pe.OPTIONAL_HEADER.BaseOfCode,
            BaseOfData                  = getattr(self._pe.OPTIONAL_HEADER, "BaseOfData", None),
            ImageBase                   = self._pe.OPTIONAL_HEADER.ImageBase,
            SectionAlignment            = self._pe.OPTIONAL_HEADER.SectionAlignment,
            FileAlignment               = self._pe.OPTIONAL_HEADER.FileAlignment,
            MajorOperatingSystemVersion = self._pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            MinorOperatingSystemVersion = self._pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            MajorImageVersion           = self._pe.OPTIONAL_HEADER.MajorImageVersion,
            MinorImageVersion           = self._pe.OPTIONAL_HEADER.MinorImageVersion,
            MajorSubsystemVersion       = self._pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            MinorSubsystemVersion       = self._pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            Win32VersionValue           = self._pe.OPTIONAL_HEADER.Reserved1,
            SizeOfImage                 = self._pe.OPTIONAL_HEADER.SizeOfImage,
            SizeOfHeaders               = self._pe.OPTIONAL_HEADER.SizeOfHeaders,
            CheckSum                    = self._pe.OPTIONAL_HEADER.CheckSum,
            Subsystem                   = WindowsSubsystem(self._pe.OPTIONAL_HEADER.Subsystem),
            DllCharacteristics          = DLLCharacteristics(self._pe.OPTIONAL_HEADER.DllCharacteristics),
            SizeOfStackReserve          = self._pe.OPTIONAL_HEADER.SizeOfStackReserve,
            SizeOfStackCommit           = self._pe.OPTIONAL_HEADER.SizeOfStackCommit,
            SizeOfHeapReserve           = self._pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            SizeOfHeapCommit            = self._pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            LoaderFlags                 = self._pe.OPTIONAL_HEADER.LoaderFlags,
            NumberOfRvaAndSizes         = self._pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
        )

        Sections: list[PESection] = []
        for section in self._pe.sections:
            try:
                Sections.append(PESection(
                    Name                 = section.Name.rstrip(b"\x00").decode(),
                    VirtualSize          = section.Misc_VirtualSize,
                    VirtualAddress       = section.VirtualAddress,
                    SizeOfRawData        = section.SizeOfRawData,
                    PointerToRawData     = section.PointerToRawData,
                    PointerToRelocations = section.PointerToRelocations,
                    PointerToLinenumbers = section.PointerToLinenumbers,
                    NumberOfRelocations  = section.NumberOfRelocations,
                    NumberOfLinenumbers  = section.NumberOfLinenumbers,
                    Characteristics      = PESectionCharacteristics(section.Characteristics),
                    _pefile_structure    = section,
                ))
            except UnicodeDecodeError as e:
                raise PEFormatError(f"Section name is not valid ASCII or UTF-8: {section.Name!r}") from e

        self.PeHeaders = PEHeaders(MzHeader, FileHeader, OptionalHeader, Sections)

        self.Imports: list[Import] = []
        if hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    name_or_ordinal: str | int = imp.name.decode() if imp.name is not None else imp.ordinal
                    self.Imports.append(Import(entry.dll.decode(), name_or_ordinal))

        self.Exports: list[Export] = []
        if hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.Exports.append(Export(exp.ordinal, exp.name.decode(), exp.address))

    def raw_pefile(self) -> RawPE:
        """ Get the underlying `pefile.PE` object. """
        return self._pe

    def get_resources_strings(self) -> list[str]:
        """
        Returns a list of all the strings found within the resources (if any).

        This method will scan all entries in the resources directory of the PE, if there is one, and will return a list with the strings.
        """
        return cast(list[str], self._pe.get_resources_strings())

    def get_data(self, rva: int = 0, length: int | None = None) -> bytes:
        """
        Get data regardless of the section where it lies on, without performing bound checking.

        Given a RVA and the size of the chunk to retrieve, this method will find the section where
        the *beginning of the data* lies and return the data.

        If `length` is `None`, all data until the end of the section is returned.

        :raises: :PEFormatError: The `rva` doesn't belong to any section and could not be mapped to the PE header either.
        """
        return bytes(self._pe.get_data(rva, length))

    def get_rva_from_offset(self, offset: int) -> int | None:
        """
        Get the RVA corresponding to this file offset, or None if no section contains it.
        """
        s = self.get_section_by_offset(offset)
        if not s:
            return None
        return s.get_rva_from_offset(offset)

    def get_offset_from_rva(self, rva: int) -> int | None:
        """
        Get the file offset corresponding to this RVA, or None if no section contains it.
        """
        s = self.get_section_by_rva(rva)
        if not s:
            return None
        return s.get_offset_from_rva(rva)

    def get_cstring_at_rva(self, rva: int, max_length: int = pefile.MAX_STRING_LENGTH) -> bytes | None:
        """
        Get an ASCII string located at the given address.

        No checks are performed for valid ASCII bytes, only the first null byte is found.
        """
        return cast(bytes | None, self._pe.get_string_at_rva(rva, max_length))

    def get_section_by_offset(self, offset: int) -> PESection | None:
        """
        Get the section containing the given file offset.
        """
        for section in self.PeHeaders.Sections:
            if section.contains_offset(offset):
                return section
        return None

    def get_section_by_rva(self, rva: int) -> PESection | None:
        """
        Get the section containing the given address.
        """
        for section in self.PeHeaders.Sections:
            if section.contains_rva(rva):
                return section
        return None

    def get_section_by_name(self, name: str) -> PESection | None:
        """
        Get the section with the given name (or None).
        """
        for section in self.PeHeaders.Sections:
            if section.Name == name:
                return section
        return None

    def is_exe(self) -> bool:
        """
        Check whether the file is a standard executable.

        This will return true only if the file has the `IMAGE_FILE_EXECUTABLE_IMAGE` flag
        set and the `IMAGE_FILE_DLL` not set and the file does not appear to be a driver
        either.
        """
        return cast(bool, self._pe.is_exe())

    def is_dll(self) -> bool:
        """
        Check whether the file is a standard DLL.

        This will return true only if the image has the `IMAGE_FILE_DLL` flag set.
        """
        return cast(bool, self._pe.is_dll())

    def is_driver(self) -> bool:
        """
        Check whether the file is a Windows driver.

        This will return true only if there are "reliable indicators" of the image being a driver.
        """
        return cast(bool, self._pe.is_driver())

    def is_32bit(self) -> bool:
        """
        Check whether the file is a PE32 (a 32-bit PE).
        """
        return self.PeHeaders.OptionalHeader.Magic == OptionalHeaderPEMagic.OPTIONAL_HEADER_MAGIC_PE32

    def is_64bit(self) -> bool:
        """
        Check whether the file is a PE32+ (a 64-bit PE).
        """
        return self.PeHeaders.OptionalHeader.Magic == OptionalHeaderPEMagic.OPTIONAL_HEADER_MAGIC_PE64

    def is_x86(self) -> bool:
        """
        Check whether the Machine field of the COFF File Header matches the x86 (i386) architecture.
        """
        return self.PeHeaders.FileHeader.Machine == CoffFileMachineType.IMAGE_FILE_MACHINE_I386

    def is_x64(self) -> bool:
        """
        Check whether the Machine field of the COFF File Header matches the x64 (amd64) architecture.
        """
        return self.PeHeaders.FileHeader.Machine == CoffFileMachineType.IMAGE_FILE_MACHINE_AMD64

    def get_overlay_data_start_offset(self) -> int | None:
        """
        Get the offset of data appended to the file and not contained within
        the area described in the headers.
        """
        return cast(int | None, self._pe.get_overlay_data_start_offset())

    def get_overlay(self) -> bytes | None:
        """
        Get the data appended to the file and not contained within the area described
        in the headers.
        """
        overlay = self._pe.get_overlay()
        return bytes(overlay) if overlay is not None else None

    def trim(self) -> bytes:
        """
        Return the just data defined by the PE headers, removing any overlaid data.
        """
        return bytes(self._pe.trim())
