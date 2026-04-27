#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <string>
#include "Disassembler.h"

struct Instruction
{
	uint64_t address;
	std::vector<uint8_t> bytes;
	std::string mnemonic;
	std::string operands;
	size_t length;
	bool isValid;
};

enum class Architecture
{
	X86_32,
	ARM_32,
	INVALID_ARCH
};

class Disassembler
{
public:
	virtual ~Disassembler() = default;
	virtual Instruction decodeNext(const uint8_t* buffer, size_t bufferLen, uint64_t virtualAddr) = 0;
};