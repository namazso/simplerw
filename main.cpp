#include <ntifs.h>
#include <ntddk.h>
#include <cstdint>
#include "shared.hpp"
#include <algorithm>

EX_CALLBACK_FUNCTION registry_callback;

extern "C" NTSTATUS NTKERNELAPI MmCopyVirtualMemory(
  PEPROCESS SourceProcess,
  PVOID SourceAddress,
  PEPROCESS TargetProcess,
  PVOID TargetAddress,
  SIZE_T BufferSize,
  KPROCESSOR_MODE PreviousMode,
  PSIZE_T ReturnSize
);

extern "C" PPEB NTKERNELAPI PsGetProcessPeb(
  PEPROCESS Process
);

extern "C" PVOID NTKERNELAPI RtlPcToFileHeader(
  PVOID PcValue,
  PVOID *BaseOfImage
);

void* get_trampoline(void* pe);

static NTSTATUS write_to_process(PEPROCESS target_process, PVOID target_address, PVOID source_address, SIZE_T size)
{
  if (intptr_t(target_address) <= 0)
    return STATUS_ACCESS_DENIED;

  NTSTATUS status = STATUS_SUCCESS;
  KAPC_STATE state;

  const auto is_current_process = target_process == PsGetCurrentProcess();

  if(!is_current_process)
    KeStackAttachProcess(target_process, &state);

  __try
  {
    memcpy(target_address, source_address, size);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    status = STATUS_ACCESS_VIOLATION;
  }

  if (!is_current_process)
    KeUnstackDetachProcess(&state);

  return status;
}

static uint64_t g_magic = 0;

static LARGE_INTEGER cookie;

NTSTATUS registry_callback(
  PVOID CallbackContext,
  PVOID Argument1,
  PVOID Argument2
)
{
  UNREFERENCED_PARAMETER(CallbackContext);
  auto retval = STATUS_SUCCESS;

  if((uintptr_t)Argument1 == RegNtPreSetValueKey)
  {
    const auto set_info = PREG_SET_VALUE_KEY_INFORMATION(Argument2);

    if(g_magic == 0)
    {
      if(set_info->DataSize >= sizeof(CmdSetMagic))
      {
        const auto cmd = (CmdSetMagic*)set_info->Data;

        if (cmd->magic_initial == k_magic_initial)
        {
          g_magic = cmd->new_magic;
          retval = STATUS_ACCESS_DENIED;
        }
      }
    }
    else
    {
      if (set_info->DataSize >= sizeof(CmdVmOperations))
      {
        const auto cmd = (CmdVmOperations*)set_info->Data;

        if(cmd->magic == g_magic)
        {
          // this is a magic operation, make sure to not actually apply the change
          retval = STATUS_ACCESS_DENIED;

          PEPROCESS local;

          auto status = PsLookupProcessByProcessId((HANDLE)(uintptr_t)cmd->local_pid, &local);

          if (NT_SUCCESS(status))
          {
            PEPROCESS remote;

            status = PsLookupProcessByProcessId((HANDLE)(uintptr_t)cmd->remote_pid, &remote);

            if (NT_SUCCESS(status))
            {
              const auto count = (set_info->DataSize - sizeof(CmdVmOperations)) / sizeof(VmOperation) + 1;

              for (auto i = 0u; i < count; ++i)
              {
                const auto current = &cmd->ops[i];

                auto target_process = remote;
                auto target_address = current->remote_address;

                auto source_process = local;
                auto source_address = current->local_address;

                switch(current->type)
                {
                case VmOperationRead:
                  std::swap(target_process, source_process);
                  std::swap(target_address, source_address);
                case VmOperationWrite:
                  {
                    const auto size = current->size;

                    const auto result_address = current->status;
                    VmOperationResult result{};
                    SIZE_T return_size = 0;

                    result.status = MmCopyVirtualMemory(
                      source_process, source_address,
                      target_process, target_address,
                      size, UserMode, &return_size
                    );

                    result.result_bytes = (uint32_t)return_size;

                    write_to_process(local, result_address, &result, sizeof(result));
                  }
                  break;
                case VmOperationGetRemotePeb:
                  {
                    auto peb = PsGetProcessPeb(remote);
                    SIZE_T return_size;

                    write_to_process(local, source_address, &peb, sizeof(peb));
                  }
                  break;
                default: ;
                }
              }

              ObDereferenceObject(remote);
            }

            ObDereferenceObject(local);
          }
        }
      }
    }
  }

  return retval;
}

extern "C"
NTSTATUS EntryPoint()
{
  void* ntos;
  ntos = RtlPcToFileHeader((void*)&RtlPcToFileHeader, &ntos);
  const auto trampoline = get_trampoline(ntos);
  return CmRegisterCallback((PEX_CALLBACK_FUNCTION)trampoline, (void*)&registry_callback, &cookie);
}
