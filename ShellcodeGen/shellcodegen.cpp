#include <windows.h>
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <string.h>

enum class LANG{
	PYTHON,
	CPP,
	VBSCRIPT,
	POWERSHELL,
	JAVASCRIPT
};

struct Shellcode {
	PVOID shellcodeData{nullptr};
	size_t shellcodeLen{0};

	~Shellcode() {
		if(shellcodeData)
			delete[] shellcodeData;
	}
};

static Shellcode* pShellCode;

bool parse_pe_file(std::string const& pe_file) {
	PIMAGE_DOS_HEADER DH; // pe file dos header
	PIMAGE_NT_HEADERS NH; // pe file nt header
	PIMAGE_SECTION_HEADER SH; // pe file section header

	HANDLE hPE = CreateFileA(pe_file.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if (hPE == INVALID_HANDLE_VALUE) {
		std::cerr << std::hex << "[*]Unable to open pe file. Error Code => 0x" << GetLastError() << '\n';
		return false;
	}

	pShellCode = new Shellcode();
	if (pShellCode != nullptr) {
		DWORD fileSize = GetFileSize(hPE, 0);
		PBYTE pBuffer = new BYTE[fileSize];
		DWORD bRead = 0;

		if (!ReadFile(hPE, pBuffer, fileSize, &bRead, NULL)) {
			std::cerr << std::hex << "[*]Unable to read pe file. Error Code => 0x" << GetLastError() << '\n';
			return false;
		}

		DH = reinterpret_cast<PIMAGE_DOS_HEADER>(pBuffer);
		if (DH->e_magic != IMAGE_DOS_SIGNATURE) {
			std::cerr << "[*]File is not a pe file. Exiting...\n";
			return false;
		}

		NH = reinterpret_cast<PIMAGE_NT_HEADERS>(DWORD(pBuffer) + DH->e_lfanew);
		if (NH->Signature != IMAGE_NT_SIGNATURE) {
			std::cerr << "[*]NT headers might be corrupted. Exiting...\n";
			return false;
		}

		/*Get number of sections must be equal to 1*/
		WORD number_of_sections = NH->FileHeader.NumberOfSections;
		if (number_of_sections == 1) {
			const char* pSectionName = ".flat";
			SH = reinterpret_cast<PIMAGE_SECTION_HEADER>(DWORD(pBuffer) + DH->e_lfanew + 248 + (1*40));
			if (memcmp(SH->Name, pSectionName, strlen(pSectionName))) {
				pShellCode->shellcodeData = new BYTE[SH->SizeOfRawData];
				void* dest = memcpy(pShellCode->shellcodeData, (pBuffer + SH->PointerToRawData), SH->SizeOfRawData);
				if (dest) {
					pShellCode->shellcodeLen = strlen(reinterpret_cast<char*>(pShellCode->shellcodeData));
					std::cout << "[*].flat section successfully copied "<< SH->SizeOfRawData << "to buffer\n";
					return true;
				}
				std::cerr << "[*]Unable to copy section data\n";
				delete[] pShellCode->shellcodeData;
			}
		}
	}
	
	return false;
}

bool generate_shellcode_array(std::string const& save_to, std::string const& arr_name, std::string const& lang) {
	if (pShellCode->shellcodeData == nullptr)
		return false;
	std::ofstream out(save_to);
	if (!out.is_open()) {
		std::cerr << "File " << save_to << " failed to open\n";
		return false;
	}
	out << "unsigned char " << arr_name.c_str() << " = {";
	
	PBYTE shellcode = new BYTE[pShellCode->shellcodeLen];
	ZeroMemory(shellcode, pShellCode->shellcodeLen);

	void* dest = memcpy(shellcode, reinterpret_cast<PBYTE>(pShellCode->shellcodeData), pShellCode->shellcodeLen);
	if (dest == nullptr) {
		return false;
	}
	for (int i = 0; i < pShellCode->shellcodeLen; i++) {
		if (i != 0)out << ',';
		if (i % 12)out << "\n\t";
		out << std::hex << "0x" << shellcode[i];
	}

	out << "\n\t};\n";

	delete[] shellcode;
	out.close();
}

int main(int argc, char** argv) {
	if (argc < 2) {
		std::cerr << "Usage: " <<  argv[0] << "[input_file] [lang] [array_name] [ output_file]\n";
		return 1;
	}

	std::string const input_file(argv[1]);
	std::string const output_file(argv[4]);
	std::string const array_name(argv[2]);
	std::string const lang(argv[3]);

	bool bSuccess = parse_pe_file(input_file) && 
		generate_shellcode_array(output_file, array_name, lang);

	bSuccess ? std::cout << "Successfully created shellcode array from pe file "<<
		input_file << '\n': std::cerr << "Unable to parse pe file and create shellcode array\n";

	delete pShellCode;
	return 0;
}