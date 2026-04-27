#pragma once

#include <string>
#include "Disassembler.h"
#include "DisassemblerUtils.h"
#include <stdexcept>
#include "ElfDefines.h"
#include <cstring>

class ArchiDetector
{
	public:
		static Architecture detectArchitecture(const std::string& filePath);
};