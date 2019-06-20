
#include <Windows.h>
#include <fstream>
#include <memory>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

template<class T = void*>
T RvaToVa(PIMAGE_NT_HEADERS nt_headers, char* image_base, uintptr_t rva)
{
	auto getEnclosingSectionHeader = [&]() -> PIMAGE_SECTION_HEADER
	{
		auto section = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1);

		for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
		{
			auto size = section->Misc.VirtualSize;
			if (!size)
				size = section->SizeOfRawData;

			if (rva >= section->VirtualAddress && rva < static_cast<uintptr_t>(section->VirtualAddress) + size)
				return section;
		}

		return nullptr;
	};

	const PIMAGE_SECTION_HEADER sectionHeader = getEnclosingSectionHeader();
	if (sectionHeader == nullptr)
		return 0;

	return reinterpret_cast<T>(image_base + rva - static_cast<uintptr_t>(sectionHeader->VirtualAddress) + sectionHeader->PointerToRawData);
}

int main()
{
	char systemDir[MAX_PATH];
	if (!GetSystemDirectoryA(systemDir, MAX_PATH))
		return 1;

	std::ifstream stream(std::string(systemDir) + "\\ntdll.dll", std::ifstream::binary);
	if (!stream.is_open())
		return 1;

	stream.seekg(0, stream.end);
	const auto size = stream.tellg();
	stream.seekg(0, stream.beg);

	std::unique_ptr<char> image(new char[size]);

	stream.read(image.get(), size);
	stream.close();

	const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(image.get() + reinterpret_cast<PIMAGE_DOS_HEADER>(image.get())->e_lfanew);
	const auto optionalHeader = &ntHeaders->OptionalHeader;
	const auto fileHeader = &ntHeaders->FileHeader;

	if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
		return 1;

	const auto t = std::time(nullptr);
	tm time;
	localtime_s(&time, &t);
	std::stringstream ss;
	ss << std::put_time(&time, "Syscall_Dump_%FT%H%M%S%z.txt");
	std::ofstream output(ss.str());

	const auto exportDir = RvaToVa<PIMAGE_EXPORT_DIRECTORY>(ntHeaders, image.get(), optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	const auto funcTable = RvaToVa<DWORD*>(ntHeaders, image.get(), exportDir->AddressOfFunctions);
	const auto ordTable = RvaToVa<WORD*>(ntHeaders, image.get(), exportDir->AddressOfNameOrdinals);
	const auto nameTable = RvaToVa<DWORD*>(ntHeaders, image.get(), exportDir->AddressOfNames);

	for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
	{
		const auto functionName = RvaToVa<char*>(ntHeaders, image.get(), nameTable[i]);
		const auto ordinal = ordTable[i];
		const auto functionOffset = funcTable[ordinal];

		const auto function = RvaToVa<uint8_t*>(ntHeaders, image.get(), functionOffset);
		/*
			mov r10, rcx
			mov eax, index		
		*/
		if (function[0] == 0x4C && function[1] == 0x8B && function[2] == 0xD1 && function[3] == 0xB8)	
			output << functionName << ": 0x" << std::hex << *reinterpret_cast<uint32_t*>(function + 4) << std::endl;
	}
	output.close();

	return 0;
}