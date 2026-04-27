#pragma once

#include <string>
#include <cstdint>

#define MAX_HEX_STRING_LENGTH 20

class DisassemblerUtils
{
public:
	static std::string decToHexString(uint64_t number);
};