#include <ntifs.h>
#include <ntddk.h>

typedef struct _IMAGE_DOS_HEADER {    // DOS .EXE header
  USHORT e_magic;                     // Magic number
  USHORT e_cblp;                      // Bytes on last page of file
  USHORT e_cp;                        // Pages in file
  USHORT e_crlc;                      // Relocations
  USHORT e_cparhdr;                   // Size of header in paragraphs
  USHORT e_minalloc;                  // Minimum extra paragraphs needed
  USHORT e_maxalloc;                  // Maximum extra paragraphs needed
  USHORT e_ss;                        // Initial (relative) SS value
  USHORT e_sp;                        // Initial SP value
  USHORT e_csum;                      // Checksum
  USHORT e_ip;                        // Initial IP value
  USHORT e_cs;                        // Initial (relative) CS value
  USHORT e_lfarlc;                    // File address of relocation table
  USHORT e_ovno;                      // Overlay number
  USHORT e_res[4];                    // Reserved words
  USHORT e_oemid;                     // OEM identifier (for e_oeminfo)
  USHORT e_oeminfo;                   // OEM information; e_oemid specific
  USHORT e_res2[10];                  // Reserved words
  LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
  USHORT    Machine;
  USHORT    NumberOfSections;
  ULONG     TimeDateStamp;
  ULONG     PointerToSymbolTable;
  ULONG     NumberOfSymbols;
  USHORT    SizeOfOptionalHeader;
  USHORT    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  ULONG   VirtualAddress;
  ULONG   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  USHORT      Magic;
  UCHAR       MajorLinkerVersion;
  UCHAR       MinorLinkerVersion;
  ULONG       SizeOfCode;
  ULONG       SizeOfInitializedData;
  ULONG       SizeOfUninitializedData;
  ULONG       AddressOfEntryPoint;
  ULONG       BaseOfCode;
  ULONGLONG   ImageBase;
  ULONG       SectionAlignment;
  ULONG       FileAlignment;
  USHORT      MajorOperatingSystemVersion;
  USHORT      MinorOperatingSystemVersion;
  USHORT      MajorImageVersion;
  USHORT      MinorImageVersion;
  USHORT      MajorSubsystemVersion;
  USHORT      MinorSubsystemVersion;
  ULONG       Win32VersionValue;
  ULONG       SizeOfImage;
  ULONG       SizeOfHeaders;
  ULONG       CheckSum;
  USHORT      Subsystem;
  USHORT      DllCharacteristics;
  ULONGLONG   SizeOfStackReserve;
  ULONGLONG   SizeOfStackCommit;
  ULONGLONG   SizeOfHeapReserve;
  ULONGLONG   SizeOfHeapCommit;
  ULONG       LoaderFlags;
  ULONG       NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
  ULONG Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
  UCHAR   Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    ULONG   PhysicalAddress;
    ULONG   VirtualSize;
  } Misc;
  ULONG   VirtualAddress;
  ULONG   SizeOfRawData;
  ULONG   PointerToRawData;
  ULONG   PointerToRelocations;
  ULONG   PointerToLinenumbers;
  USHORT  NumberOfRelocations;
  USHORT  NumberOfLinenumbers;
  ULONG   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.

void* get_trampoline(void* pe)
{
  const auto dos = PIMAGE_DOS_HEADER(pe);
  const auto nt = PIMAGE_NT_HEADERS((char*)pe + dos->e_lfanew);

  const auto section_header = PIMAGE_SECTION_HEADER(nt + 1);
  const auto section_count = nt->FileHeader.NumberOfSections;

  for (auto i = 0u; i < section_count; i++)
  {
    if (!(section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
      continue;

    if (!(section_header[i].Characteristics & IMAGE_SCN_MEM_NOT_PAGED))
      continue;

    const auto begin = (char*)pe + section_header[i].VirtualAddress;
    const auto end = begin + section_header[i].SizeOfRawData;

    for(auto it = begin; it < end - 1; ++it)
    {
      if (*(USHORT*)it == 0xE1FF)
        return it;
    }
  }


  return nullptr;
}