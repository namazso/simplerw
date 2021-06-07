#pragma once
#include <windows.h>
#include "../shared.hpp"
#include <system_error>
#include <random>
#include <deque>

class SimpleRWInstance
{
  HKEY _reg_handle = nullptr;
  uint64_t _magic = 0;
  constexpr static std::string::size_type _random_string_len = 16;
  std::string _random_string;

public:
  void init()
  {
    _magic = std::random_device{}();

    auto status = RegOpenKeyExA(
      HKEY_CURRENT_USER,
      "Environment", // can be anything
      0,
      KEY_ALL_ACCESS,
      &_reg_handle
    );

    if (status != ERROR_SUCCESS)
      throw std::system_error(status, std::system_category());

    CmdSetMagic cmd;

    cmd.new_magic = _magic;

    _random_string.resize(_random_string_len);
    std::generate_n(_random_string.begin(), _random_string_len, []() { return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[rand() % 52]; });

    status = RegSetValueExA(
      _reg_handle,
      _random_string.c_str(),
      0,
      REG_BINARY,
      (BYTE*)&cmd,
      sizeof(cmd)
    );

    if (status == ERROR_SUCCESS)
      throw std::runtime_error("Driver not running");
  }

  ~SimpleRWInstance()
  {
    CloseHandle(_reg_handle);
  }

  void execute_query(CmdVmOperations* ops, DWORD size)
  {
    ops->magic = _magic;

    auto status = RegSetValueExA(
      _reg_handle,
      _random_string.c_str(),
      0,
      REG_BINARY,
      (BYTE*)ops,
      size
    );
  }
};

class RemoteProcess
{
  CmdVmOperations _cmdhead;

  std::deque<VmOperation> _ops;

public:
  RemoteProcess(DWORD pid)
  {
    _cmdhead.local_pid = GetCurrentProcessId();
    _cmdhead.remote_pid = pid;
  }

  void read(void* to, void* from, size_t size, VmOperationResult* result = nullptr)
  {
    _ops.push_back({ VmOperationRead, (uint32_t)size, result, to, from });
  }

  void write(void* to, void* from, size_t size, VmOperationResult* result = nullptr)
  {
    _ops.push_back({ VmOperationWrite, (uint32_t)size, result, from, to });
  }

  void get_peb(void** to)
  {
    _ops.push_back({ VmOperationGetRemotePeb, 0, nullptr, to, nullptr });
  }

  void run(SimpleRWInstance& srw)
  {
    if(!_ops.empty())
    {
      const auto mem_size = sizeof(_cmdhead) + (_ops.size() - 1) * sizeof(VmOperation);
      const auto mem = std::make_unique<BYTE[]>(mem_size);

      const auto ptr = (CmdVmOperations*)mem.get();

      *ptr = _cmdhead;
      for (auto i = 0u; i < _ops.size(); ++i)
        ptr->ops[i] = _ops[i];

      srw.execute_query(ptr, (DWORD)mem_size);
    }
  }
};