#pragma once
#include <cstdint>

// generated with random.org guaranteed secure :))))
constexpr static uint64_t k_magic_initial = 0x293f819e4d70015a;

enum VmOperationType : uint32_t
{
  VmOperationRead,
  VmOperationWrite,
  VmOperationGetRemotePeb
};

struct VmOperationResult
{
  NTSTATUS status;
  uint32_t result_bytes;
};

struct VmOperation
{
  VmOperationType type;
  uint32_t size;
  VmOperationResult* status;
  void* local_address;
  void* remote_address;
};

struct CmdVmOperations
{
  uint64_t magic;
  uint32_t local_pid;
  uint32_t remote_pid;

  VmOperation ops[1];
};

struct CmdSetMagic
{
  uint64_t magic_initial = k_magic_initial;
  uint64_t new_magic = 0;
};