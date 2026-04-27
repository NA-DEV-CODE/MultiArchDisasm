#include "DisassemblerUtils.h"

std::string DisassemblerUtils::decToHexString(uint64_t number)
{
	char hexString[MAX_HEX_STRING_LENGTH] = { 0 };
	snprintf(hexString, sizeof(hexString), "0x%llx", number);
	return std::string(hexString);
}