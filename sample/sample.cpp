#include <windows.h>
#include <cstdio>
#include <TlHelp32.h>
#include "remote_process.hpp"

SimpleRWInstance g_srw;

int main()
{
  g_srw.init();

  DWORD pid;

  printf("Enter target pid: ");
  scanf_s("%lX", &pid);

  RemoteProcess remote{ pid };

  void* peb = nullptr;
  remote.get_peb(&peb);
  remote.run(g_srw);
  printf("PEB is at %p\n", peb);

  void* image_base = nullptr;
  remote.read(&image_base, (char*)peb + 16 /* ImageBaseAddress */, sizeof(image_base));
  remote.run(g_srw);
  printf("Image is at %p\n", image_base);

  BYTE dos_magic[2]{};
  BYTE first_bytes[4]{};

  remote.read(&dos_magic, image_base, sizeof(dos_magic));
  remote.read(first_bytes, (char*)image_base + 0x1000, sizeof(first_bytes));
  remote.run(g_srw);

  printf("The dos magic is %c%c, first 4 bytes of next page are %02hhX %02hhX %02hhX %02hhX.\n",
    dos_magic[0], dos_magic[1], first_bytes[0], first_bytes[1], first_bytes[2], first_bytes[3]);
}
