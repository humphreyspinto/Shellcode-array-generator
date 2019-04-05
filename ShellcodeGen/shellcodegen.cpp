#include <windows.h>
#include <iostream>
#include <fstream>
#include <map>
#include <regex>
#include <string>
#include <string.h>

enum class LANG_ID{
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
		if(shellcodeData != nullptr)
			delete[] shellcodeData;
	}
};

static Shellcode* g_pShellCode;
static std::map<std::string const, LANG_ID> g_Languages{ {"python", LANG_ID::PYTHON}, 
	{"cpp", LANG_ID::CPP}, {"vbscript", LANG_ID::VBSCRIPT}, {"javascript", LANG_ID::JAVASCRIPT}, 
		{"powershell", LANG_ID::POWERSHELL} };

bool parse_pe_file(std::string const& pe_file) {
	PIMAGE_DOS_HEADER DH; // pe file dos header
	PIMAGE_NT_HEADERS NH; // pe file nt header
	PIMAGE_SECTION_HEADER SH; // pe file section header

	HANDLE hPE = CreateFileA(pe_file.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if (hPE == INVALID_HANDLE_VALUE) {
		std::cerr << std::hex << "[*]Unable to open pe file. Error Code => 0x" << GetLastError() << '\n';
		return false;
	}

	g_pShellCode = new Shellcode();
	if (g_pShellCode != nullptr) {
		DWORD fileSize = GetFileSize(hPE, 0);
		PBYTE pBuffer = new BYTE[fileSize];
		DWORD bRead = 0;

		if (!ReadFile(hPE, pBuffer, fileSize, &bRead, NULL)) {
			std::cerr << std::hex << "[*]Unable to read pe file. Error Code => 0x" << GetLastError() << '\n';
			return false;
		}

		DH = reinterpret_cast<PIMAGE_DOS_HEADER>(pBuffer);
		if (DH->e_magic != IMAGE_DOS_SIGNATURE) {
			std::cerr << "[*]File is not a valid pe file might be corrupted. Exiting...\n";
			return false;
		}

		NH = reinterpret_cast<PIMAGE_NT_HEADERS>(DWORD(pBuffer) + DH->e_lfanew);
		if (NH->Signature != IMAGE_NT_SIGNATURE) {
			std::cerr << "[*]NT headers might be corrupted. Exiting...\n";
			return false;
		}

		/*Get number of sections. must be equal to 1*/
		WORD number_of_sections = NH->FileHeader.NumberOfSections;
		if (number_of_sections == 1) {
			const char* pSectionName = ".flat";
			SH = reinterpret_cast<PIMAGE_SECTION_HEADER>(DWORD(pBuffer) + DH->e_lfanew + 248 + (1*40));
			if (memcmp(SH->Name, pSectionName, strlen(pSectionName))) {
				g_pShellCode->shellcodeData = new BYTE[SH->SizeOfRawData];
				void* dest = memcpy(g_pShellCode->shellcodeData, (pBuffer + SH->PointerToRawData), SH->SizeOfRawData);
				if (dest) {
					g_pShellCode->shellcodeLen = strlen(reinterpret_cast<char*>(g_pShellCode->shellcodeData));
					std::cout << "[*].flat section successfully copied "<< SH->SizeOfRawData << "to buffer\n";
					return true;
				}
				std::cerr << "[*]Unable to copy section data\n";
				delete[] g_pShellCode->shellcodeData;
			}
		}
	}
	
	return false;
}

bool generate_shellcode_array(std::string const& save_to, std::string const& arr_name, std::string const& lang) {
	if (g_pShellCode->shellcodeData == nullptr)
		return false;
	std::ofstream out(save_to);
	if (!out.is_open()) {
		std::cerr << "File " << save_to << " failed to open\n";
		return false;
	}
	
	out << "unsigned char " << arr_name.c_str() << " = {";
	
	PBYTE shellcode = new BYTE[g_pShellCode->shellcodeLen];
	ZeroMemory(shellcode, g_pShellCode->shellcodeLen);

	void* dest = memcpy(shellcode, reinterpret_cast<PBYTE>(g_pShellCode->shellcodeData), g_pShellCode->shellcodeLen);
	if (dest == nullptr) {
		return false;
	}
	for (unsigned int i = 0; i < g_pShellCode->shellcodeLen, shellcode[i] != 0x0; i++) {
		if (i != 0)out << ',';
		if (i % 12)out << "\n\t";
		out << std::hex << "0x" << shellcode[i];
	}

	out << "\n\t};\n";

	delete[] shellcode;
	out.close();

	return true;
}

int main(int argc, char** argv) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << "[input_file] [lang] [array_name] [ output_file]\n";
		return 1;
	}

	std::string const input_file{ argv[1] }, output_file{ argv[4] }
		, array_name{ argv[3] }, lang{ argv[2] };

	//validate input with regexes
	std::regex lang_reg{ "^[a-zA-Z_$][a-zA-Z_$0-9]*$"};
	if (!std::regex_match(array_name.cbegin(), array_name.cend(), lang_reg)) {
			std::cerr << "[*]Array name is invalid should start with valid characters\n";
			return 1;
	}

	bool bSuccess = g_Languages.find(lang) != g_Languages.end() && parse_pe_file(input_file) &&
		generate_shellcode_array(output_file, array_name, lang);

	bSuccess ? std::cout << "[*]Successfully created shellcode array from pe file "<<
		input_file << '\n': std::cerr << "[*]Unable to parse pe file and create shellcode array\n";

	delete g_pShellCode;
	return 0;
}