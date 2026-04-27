#include "ArchiDetector.h"


Architecture ArchiDetector::detectArchitecture(const std::string& filePath)
{
	FILE* file;
	file = fopen(filePath.c_str(), "rb");
	if (!file) 
	{
		throw std::runtime_error("Failed to open file: " + filePath);
	}
	bool is32Bit = false;
	if (!file) 
	{
		throw std::runtime_error("Failed to open file: " + filePath);
	}
	uint8_t elfHeader[ELF_HEADER_LENGTH];
	size_t bytesRead = fread(elfHeader, 1, ELF_HEADER_LENGTH, file);
	fclose(file);
	for(int i = 0; i < 4; i++)
	{
		if (elfHeader[i] != ELF_MAGIC[i])
		{
			return Architecture::INVALID_ARCH;
		}
	}
	is32Bit = (ELF_32_BIT_CLASS == elfHeader[ELF_BIT_ARCHITECTURE_INDEX]);
	if(!is32Bit && ELF_64_BIT_CLASS != elfHeader[ELF_BIT_ARCHITECTURE_INDEX])
	{
		return Architecture::INVALID_ARCH;
	}
	if(elfHeader[ENDIAN_INFO_INDEX] != LITTLE_ENDIAN_FLAG)
	{
		return Architecture::INVALID_ARCH;
	}

	uint16_t archId;
	std::memcpy(&archId, &elfHeader[ARCHITECTURE_ID_INDEX], AMOUNT_OF_ARCHITECTURE_BYTES);

	if(X86_ARCHITECTURE_ID == archId)
	{
		return Architecture::X86_32;
	}
	else if(AARCH64_ARCHITECTURE_ID == archId)
	{
		return Architecture::ARM_32;
	}
	else
	{
		return Architecture::INVALID_ARCH;
	}

}