#include <windows.h>
#include <iostream>
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
		if (shellcodeData != nullptr) {
			delete[] shellcodeData;
			shellcodeData = nullptr;
		}
	}
};

static Shellcode* g_pShellCode{nullptr};

static std::map<std::string const, LANG_ID> g_Languages{ {"python", LANG_ID::PYTHON}, 
	{"cpp", LANG_ID::CPP}, {"vbscript", LANG_ID::VBSCRIPT}, {"javascript", LANG_ID::JAVASCRIPT}, 
		{"powershell", LANG_ID::POWERSHELL} };

bool parse_pe_file(std::string const& pe_file) {
	PIMAGE_DOS_HEADER DH{nullptr}; // pe file dos header
	PIMAGE_NT_HEADERS NH{nullptr}; // pe file nt header
	PIMAGE_SECTION_HEADER SH{nullptr}; // pe file section header

	HANDLE hPE = CreateFileA(pe_file.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if (hPE == INVALID_HANDLE_VALUE) {
		std::cerr << std::hex << "[*]Unable to open pe file. Error Code => 0x" << GetLastError() << '\n';
		return false;
	}

	
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
			char const* pSectionName = ".flat";
			/*Get the .flat section if it exists in the pe file*/
			SH = reinterpret_cast<PIMAGE_SECTION_HEADER>(DWORD(pBuffer) + DH->e_lfanew + 248); // get to first section offset
			if (memcmp(SH->Name, pSectionName, strlen(pSectionName)) == 0) {
				g_pShellCode->shellcodeData = new BYTE[SH->SizeOfRawData];
				g_pShellCode->shellcodeLen = SH->SizeOfRawData;
				void* copy = memcpy(g_pShellCode->shellcodeData,
					reinterpret_cast<void*>(DWORD(pBuffer) + SH->PointerToRawData),
					g_pShellCode->shellcodeLen);
				if (copy != nullptr)
					return true;
			}
			else {
				std::cerr << "[*].flat section not found. Use flat assembler(fasm) to generate pe file from shellcode\n";
				return false;
			}
		}
	}
	return false;
}

bool generate_shellcode_array(std::string const& save_to, std::string const& arr_name, 
		std::map<std::string const, LANG_ID>::iterator& language) {
	if (g_pShellCode->shellcodeData == nullptr)
		return false;

	FILE* out_s = fopen(save_to.c_str(), "w");
	if (out_s == nullptr) {
		std::cerr << "[*]File " << save_to << " failed to open\n";
		return false;
	}
	std::pair<std::string, std::string> arr_fmt;
	switch (language->second){
	case LANG_ID::CPP:
		arr_fmt.first = "unsigned char " + arr_name + " = {";
		arr_fmt.second = "\n};\n";
		break;
	case LANG_ID::JAVASCRIPT:
		arr_fmt.first = arr_name + " = {";
		arr_fmt.second = "\n};\n";
		break;
	case LANG_ID::POWERSHELL:
		arr_fmt.first = "[Byte[]] " + arr_name + " = @(";
		arr_fmt.second = "\n)";
		break;
	case LANG_ID::PYTHON:
		arr_fmt.first = arr_name + " = [";
		arr_fmt.second = "\n]\n";
		break;
	case LANG_ID::VBSCRIPT:
		arr_fmt.first = "";
		arr_fmt.second = "";
		break;
	default:
		break;
	}

	
	PBYTE shellcode = new BYTE[g_pShellCode->shellcodeLen];
	ZeroMemory(shellcode, g_pShellCode->shellcodeLen);

	void* dest = memcpy(shellcode, reinterpret_cast<PBYTE>(g_pShellCode->shellcodeData), 
		g_pShellCode->shellcodeLen);

	if (dest == nullptr) {
		return false;
	}

	fprintf_s(out_s, arr_fmt.first.c_str());

	for (unsigned int i = 0; i < g_pShellCode->shellcodeLen, shellcode[i] != 0x00; i++) {
		if (i != 0)
			fprintf_s(out_s, ", ");
		if (i % 12 == 0) // each row will have 12 elements
			fprintf_s(out_s, "\n\t");
		fprintf_s(out_s, "0x%.2x", static_cast<BYTE>(shellcode[i]));
	}

	fprintf_s(out_s, arr_fmt.second.c_str());
	
	delete[] shellcode;
	fclose(out_s);

	return true;
}

int main(int argc, char** argv) {
	if (argc < 5) {
		std::cerr << "Usage: " << argv[0] << " [input_file] [lang] [array_name] [ output_file]\n";
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
	g_pShellCode = new Shellcode();
	ZeroMemory(g_pShellCode, sizeof(Shellcode));

	auto lang_pair = g_Languages.find(lang);

	bool bSuccess =  lang_pair != g_Languages.end() && parse_pe_file(input_file) &&
		generate_shellcode_array(output_file, array_name, lang_pair);

	bSuccess ? std::cout << "[*]Successfully created shellcode array from pe file "<<
		input_file << '\n': std::cerr << "[*]Unable to parse pe file and create shellcode array\n";
	
	delete g_pShellCode;
	return 0;
}