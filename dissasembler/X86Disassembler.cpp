#include "X86Disassembler.h"

Instruction X86Disassembler::decodeNext(const uint8_t* buffer, size_t bufferLen, uint64_t virtualAddr)
{
	currentBuffer = buffer;
	currentOffset = 0;
	maxLen = bufferLen;
	activePrefixes = { 0, 0, false, false };
	Instruction result;
	result.isValid = true;
	currentInstruction = &result;
	result.address = virtualAddr;
	decodePrefixes();
	decodeOpcode();
	result.length = currentOffset;
	result.bytes = std::vector<uint8_t>(buffer, buffer + currentOffset);
	return result;
}

void X86Disassembler::decodePrefixes()
{
	bool prefixFound = true;
	while (prefixFound && currentOffset < maxLen)
	{
		uint8_t currentByte = currentBuffer[currentOffset];
		if (checkIsPrefix(currentByte))
		{
			switch (currentByte)
			{
			case PRE_LOCK:
			case PRE_REPNE:
			case PRE_REPE:
				activePrefixes.lockRep = currentByte;
				break;

			case PRE_CS_OVERRIDE:
			case PRE_SS_OVERRIDE:
			case PRE_DS_OVERRIDE:
			case PRE_ES_OVERRIDE:
			case PRE_FS_OVERRIDE:
			case PRE_GS_OVERRIDE:
				activePrefixes.segmentOverride = currentByte;
				break;

			case PRE_OPERAND_SIZE:
				activePrefixes.hasOpSizeOverride = true;
				break;

			case PRE_ADDRESS_SIZE:
				activePrefixes.hasAddrSizeOverride = true;
				break;
			}
			currentOffset++;
		}
		else
		{
			prefixFound = false;
		}
	}
}

void X86Disassembler::decodeOpcode()
{
	if (currentOffset < maxLen)
	{
		uint8_t opcode = currentBuffer[currentOffset];

		switch (opcode)
		{
		case 0x0F:
			currentOffset++;
			decodeTwoByteOpcode();
			break;

		case 0x90:
			currentInstruction->mnemonic = "nop";
			currentOffset++;
			break;

		case 0x00: case 0x01: case 0x02: case 0x03:
			currentInstruction->mnemonic = "add";
			decodeStandardArithmetic(opcode);
			break;
		case 0x04: case 0x05:
			currentInstruction->mnemonic = "add";
			decodeImmediateToAccumulator(opcode);
			break;

		case 0x08: case 0x09: case 0x0A: case 0x0B:
			currentInstruction->mnemonic = "or";
			decodeStandardArithmetic(opcode);
			break;

		case 0x0C: case 0x0D:
			currentInstruction->mnemonic = "or";
			decodeImmediateToAccumulator(opcode);
			break;

		case 0x20: case 0x21: case 0x22: case 0x23:
			currentInstruction->mnemonic = "and";
			decodeStandardArithmetic(opcode);
			break;

		case 0x24: case 0x25:
			currentInstruction->mnemonic = "and";
			decodeImmediateToAccumulator(opcode);
			break;

		case 0x28: case 0x29: case 0x2A: case 0x2B:
			currentInstruction->mnemonic = "sub";
			decodeStandardArithmetic(opcode);
			break;

		case 0x2C: case 0x2D:
			currentInstruction->mnemonic = "sub";
			decodeImmediateToAccumulator(opcode);
			break;

		case 0x30: case 0x31: case 0x32: case 0x33:
			currentInstruction->mnemonic = "xor";
			decodeStandardArithmetic(opcode);
			break;

		case 0x34: case 0x35:
			currentInstruction->mnemonic = "xor";
			decodeImmediateToAccumulator(opcode);
			break;

		case 0x38: case 0x39: case 0x3A: case 0x3B:
			currentInstruction->mnemonic = "cmp";
			decodeStandardArithmetic(opcode);
			break;

		case 0x3C: case 0x3D:
			currentInstruction->mnemonic = "cmp";
			decodeImmediateToAccumulator(opcode);
			break;

		case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
			currentInstruction->mnemonic = "inc";
			currentInstruction->operands = getRegisterName(opcode & 0x07, false);
			currentOffset++;
			break;
		case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
			currentInstruction->mnemonic = "dec";
			currentInstruction->operands = getRegisterName(opcode & 0x07, false);
			currentOffset++;
			break;

		case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
			currentInstruction->mnemonic = "push";
			currentInstruction->operands = getRegisterName(opcode & 0x07, false);
			currentOffset++;
			break;

		case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
			currentInstruction->mnemonic = "pop";
			currentInstruction->operands = getRegisterName(opcode & 0x07, false);
			currentOffset++;
			break;

		case 0xEB:
			currentInstruction->mnemonic = "jmp";
			decodeShortRelative();
			break;

		case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
		case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
			currentInstruction->mnemonic = shortJccs[opcode & 0x0F];
			decodeShortRelative();
			break;

		case 0x80: case 0x81: case 0x82: case 0x83:
			decodeArithmeticImmediate(opcode);
			break;

		case 0x84: case 0x85:
			currentInstruction->mnemonic = "test";
			decodeStandardArithmetic(opcode);
			break;

		case 0x8D:
			currentInstruction->mnemonic = "lea";
			currentOffset++;
			decodeModRM(false, true, false);
			break;

		case 0xA8: case 0xA9:
			currentInstruction->mnemonic = "test";
			decodeImmediateToAccumulator(opcode);
			break;

		case 0xF6: case 0xF7:
			decodeGroup3(opcode);
			break;

		case 0xFE:
		case 0xFF:
			decodeGroup4And5(opcode);
			break;

		case 0x88: case 0x89: case 0x8A: case 0x8B:
			currentInstruction->mnemonic = "mov";
			decodeStandardArithmetic(opcode);
			break;

		case 0xB8: case 0xB9: case 0xBA: case 0xBB:
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
			currentInstruction->mnemonic = "mov";
			decodeMoveRegImm(opcode);
			break;

		case 0xC2:
			currentInstruction->mnemonic = "ret";
			decodeRet();
			break;

		case 0xC3:
			currentInstruction->mnemonic = "ret";
			currentOffset++;
			break;

		case 0xC6: case 0xC7:
			decodeMoveMemImm(opcode);
			break;

		case 0xD0: case 0xD1: case 0xD2: case 0xD3:
			decodeGroup2(opcode);
			break;

		case 0xE8:
			decodeCall();
			break;

		default:
			currentInstruction->mnemonic = "db";
			currentOffset++;
			break;
		}
	}
}

std::string X86Disassembler::getRegisterName(uint8_t regIndex, const bool is8Bit)
{
	regIndex &= 0x7;
	if (is8Bit)
	{
		static const std::string regs8[] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };
		return regs8[regIndex];
	}
	if (activePrefixes.hasOpSizeOverride) {
		static const std::string regs16[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
		return regs16[regIndex];
	}
	static const std::string regs32[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
	return regs32[regIndex];
}

void X86Disassembler::decodeModRM(const bool is8Bit, const bool regIsDest, bool oneOperandOnly)
{
	if (currentOffset >= maxLen)
	{
		currentInstruction->isValid = false;
		return;
	}
	std::string segmentPrefix = "";
	if (0 != activePrefixes.segmentOverride)
	{
		segmentPrefix = getSegmentOverridePrefix() + ":";
	}
	uint8_t modrm = currentBuffer[currentOffset];
	currentOffset++;
	uint8_t mode = (modrm >> 6) & 0x3;
	int8_t disp8 = 0;
	int32_t disp32 = 0;
	uint8_t reg = (modrm >> 3) & 0x7;
	uint8_t rm = modrm & 0x7;

	if (MODE_2_REGISTERS == mode)
	{
		std::string op1 = getRegisterName(reg, is8Bit);
		std::string op2 = getRegisterName(rm, is8Bit);
		if (oneOperandOnly)
			currentInstruction->operands = op2;
		else
			currentInstruction->operands = regIsDest ? (op1 + ", " + op2) : (op2 + ", " + op1);
	}
	else
	{
		std::string regName = getRegisterName(reg, is8Bit);
		std::string memContent = "";
		if (MODE_SIB == rm)
		{
			if (currentOffset >= maxLen)
			{
				currentInstruction->isValid = false;
				return;
			}
			uint8_t sib = currentBuffer[currentOffset++];
			uint8_t scale = (sib >> 6) & 0x3;
			uint8_t index = (sib >> 3) & 0x7;
			uint8_t base = sib & 0x7;
			if (MODE_RM_DISPLACEMENT == base && RI_MODE == mode)
			{
				if (currentOffset + 4 <= maxLen)
				{
					std::memcpy(&disp32, &currentBuffer[currentOffset], 4);
					memContent += DisassemblerUtils::decToHexString(disp32);
					currentOffset += 4;
				}
			}
			else
			{
				memContent += getRegisterName(base, false);
			}
			if (ESP_CODE != index)
			{
				if (MODE_RM_DISPLACEMENT != base || RI_MODE != mode)
				{
					memContent += " + ";
				}
				memContent += getRegisterName(index, false);
				if (0 < scale)
				{
					memContent += "*" + std::to_string(1 << scale);
				}
			}
		}
		else if (MODE_RM_DISPLACEMENT == rm && RI_MODE == mode)
		{
			if (currentOffset + 4 <= maxLen)
			{
				std::memcpy(&disp32, &currentBuffer[currentOffset], 4);
				memContent += DisassemblerUtils::decToHexString(disp32);
				currentOffset += 4;
			}
		}
		else
		{
			memContent += getRegisterName(rm, false);
		}

		if (MODE_ADD_BYTE == mode)
		{
			if (currentOffset < maxLen)
			{
				memcpy(&disp8, &currentBuffer[currentOffset++], sizeof(int8_t));
				if (0 != disp8)
				{
					memContent += (disp8 < 0 ? " - " : " + ") + DisassemblerUtils::decToHexString((uint8_t)std::abs(disp8));
				}
			}
		}
		else if (MODE_ADD_DWORD == mode)
		{
			if (currentOffset + 4 <= maxLen)
			{
				std::memcpy(&disp32, &currentBuffer[currentOffset], 4);
				currentOffset += 4;
				if (0 != disp32)
				{
					memContent += (disp32 < 0 ? " - " : " + ") + DisassemblerUtils::decToHexString(std::abs(disp32));
				}
			}
		}

		if (oneOperandOnly)
		{
			currentInstruction->operands = segmentPrefix + "[" + memContent + "]";
		}
		else if (regIsDest)
		{
			currentInstruction->operands = regName + ", " + segmentPrefix + "[" + memContent + "]";
		}
		else
		{
			currentInstruction->operands = segmentPrefix + "[" + memContent + "], " + regName;
		}
	}
}

void X86Disassembler::decodeStandardArithmetic(uint8_t opcode)
{
	currentOffset++;
	bool is8bit = !(opcode & 0x01);
	bool isRegDest = (opcode & 0x02);
	decodeModRM(is8bit, isRegDest, false);
}

void X86Disassembler::decodeImmediateToAccumulator(uint8_t opcode) {
	currentOffset++;
	bool is8Bit = (0x04 == opcode || 0x0C == opcode || 0x24 == opcode ||
		0x2C == opcode || 0x34 == opcode || 0x3C == opcode || 0xA8 == opcode);
	std::string reg = is8Bit ? "al" : (activePrefixes.hasOpSizeOverride ? "ax" : "eax");
	if (is8Bit)
	{
		uint8_t imm8 = currentBuffer[currentOffset++];
		currentInstruction->operands = reg + ", " + DisassemblerUtils::decToHexString(imm8);
	}
	else
	{
		uint32_t imm32 = 0;
		std::memcpy(&imm32, &currentBuffer[currentOffset], 4);
		currentOffset += 4;
		currentInstruction->operands = reg + ", " + DisassemblerUtils::decToHexString(imm32);
	}
}

std::string X86Disassembler::getSegmentOverridePrefix()
{
	switch (activePrefixes.segmentOverride)
	{
	case PRE_CS_OVERRIDE: return "cs";
	case PRE_SS_OVERRIDE: return "ss";
	case PRE_DS_OVERRIDE: return "ds";
	case PRE_ES_OVERRIDE: return "es";
	case PRE_FS_OVERRIDE: return "fs";
	case PRE_GS_OVERRIDE: return "gs";
	default: return "";
	}
}

void X86Disassembler::decodeCall()
{
	if (currentOffset + 5 > maxLen)
	{
		currentInstruction->isValid = false;
		return;
	}
	currentInstruction->mnemonic = "call";
	currentOffset++;
	int32_t relative = 0;
	std::memcpy(&relative, &currentBuffer[currentOffset], 4);
	currentOffset += 4;
	uint64_t targetAddress = currentInstruction->address + currentOffset + relative;
	currentInstruction->operands = DisassemblerUtils::decToHexString(targetAddress);
}

void X86Disassembler::decodeMoveRegImm(uint8_t opcode)
{
	uint8_t regIndex = opcode & 0x07;
	currentOffset++;
	bool is16Bit = activePrefixes.hasOpSizeOverride;
	size_t amountOfBytesToRead = is16Bit ? 2 : 4;
	if (currentOffset + amountOfBytesToRead > maxLen)
	{
		currentInstruction->isValid = false;
		return;
	}
	std::string regName = getRegisterName(regIndex, false);
	uint32_t immediate = 0;
	std::memcpy(&immediate, &currentBuffer[currentOffset], amountOfBytesToRead);
	currentOffset += amountOfBytesToRead;
	currentInstruction->operands = regName + ", " + DisassemblerUtils::decToHexString(immediate);
}

void X86Disassembler::decodeArithmeticImmediate(uint8_t opcode)
{
	currentOffset++;
	uint8_t modrm = currentBuffer[currentOffset];
	uint8_t subOpcode = (modrm >> 3) & 0x07;
	static const std::string mnemonics[] = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
	currentInstruction->mnemonic = mnemonics[subOpcode];
	decodeModRM(false, true, true);
	if (0x83 == opcode)
	{
		int8_t imm8 = (int8_t)currentBuffer[currentOffset++];
		currentInstruction->operands += ", " + DisassemblerUtils::decToHexString((uint8_t)imm8);
	}
	else
	{
		int32_t imm32 = 0;
		std::memcpy(&imm32, &currentBuffer[currentOffset], 4);
		currentOffset += 4;
		currentInstruction->operands += ", " + DisassemblerUtils::decToHexString(imm32);
	}
}

void X86Disassembler::decodeTwoByteOpcode()
{
	if (currentOffset >= maxLen)
	{
		return;
	}
	uint8_t opcode = currentBuffer[currentOffset++];
	if (opcode >= 0x80 && opcode <= 0x8F)
	{
		currentInstruction->mnemonic = jccMnemonics[opcode & 0x0F];
		if (currentOffset + 4 <= maxLen)
		{
			int32_t rel32;
			std::memcpy(&rel32, &currentBuffer[currentOffset], 4);
			currentOffset += 4;
			uint64_t target = currentInstruction->address + currentOffset + rel32;
			currentInstruction->operands = DisassemblerUtils::decToHexString(target);
		}
	}
	else if (0xB6 == opcode || 0xB7 == opcode || 0xBE == opcode || 0xBF == opcode)
	{
		currentInstruction->mnemonic = (opcode >= 0xBE) ? "movsx" : "movzx";
		bool isSrc8Bit = (0xB6 == opcode || 0xBE == opcode);
		uint8_t modrm = currentBuffer[currentOffset];
		uint8_t reg = (modrm >> 3) & 0x7;
		std::string destReg = getRegisterName(reg, false);
		decodeModRM(isSrc8Bit, true, true);
		currentInstruction->operands = destReg + ", " + currentInstruction->operands;
	}
	else if (0xAF == opcode)
	{
		currentInstruction->mnemonic = "imul";
		decodeModRM(false, true, false);
	}
	else if (0x1F == opcode)
	{
		currentInstruction->mnemonic = "nop";
		decodeModRM(false, true, true);
	}
	else
	{
		currentInstruction->mnemonic = "db";
		currentInstruction->operands = "0F " + DisassemblerUtils::decToHexString(opcode);
	}
}

void X86Disassembler::decodeGroup3(uint8_t opcode)
{
	currentOffset++;
	uint8_t modrm = currentBuffer[currentOffset];
	uint8_t subOpcode = (modrm >> 3) & 0x07;
	static const std::string group3Mnemonics[] = { "test", "test", "not", "neg", "mul", "imul", "div", "idiv" };
	currentInstruction->mnemonic = group3Mnemonics[subOpcode];
	bool is8Bit = !(opcode & 0x01);
	decodeModRM(is8Bit, true, true);
	if (0 == subOpcode || 1 == subOpcode)
	{
		if (is8Bit)
		{
			currentInstruction->operands += ", " + DisassemblerUtils::decToHexString(currentBuffer[currentOffset++]);
		}
		else
		{
			uint32_t imm = 0;
			std::memcpy(&imm, &currentBuffer[currentOffset], 4);
			currentOffset += 4;
			currentInstruction->operands += ", " + DisassemblerUtils::decToHexString(imm);
		}
	}
}

void X86Disassembler::decodeShortRelative()
{
	currentOffset++;
	if (currentOffset >= maxLen)
	{
		return;
	}
	int8_t rel8 = (int8_t)currentBuffer[currentOffset++];
	uint64_t target = currentInstruction->address + currentOffset + rel8;
	currentInstruction->operands = DisassemblerUtils::decToHexString(target);
}

void X86Disassembler::decodeMoveMemImm(uint8_t opcode)
{
	currentOffset++;
	bool is8Bit = (0xC6 == opcode);
	currentInstruction->mnemonic = "mov";
	decodeModRM(is8Bit, false, true);
	if (is8Bit)
	{
		uint8_t imm8 = currentBuffer[currentOffset++];
		currentInstruction->operands += ", " + DisassemblerUtils::decToHexString(imm8);
	}
	else
	{
		uint32_t imm32 = 0;
		std::memcpy(&imm32, &currentBuffer[currentOffset], 4);
		currentOffset += 4;
		currentInstruction->operands += ", " + DisassemblerUtils::decToHexString(imm32);
	}
}

void X86Disassembler::decodeRet()
{
	currentOffset++;
	if (currentOffset + 2 <= maxLen)
	{
		uint16_t imm16 = 0;
		std::memcpy(&imm16, &currentBuffer[currentOffset], 2);
		currentOffset += 2;
		currentInstruction->operands = DisassemblerUtils::decToHexString(imm16);
	}
}

void X86Disassembler::decodeGroup2(uint8_t opcode)
{
	currentOffset++;
	uint8_t modrm = currentBuffer[currentOffset];
	uint8_t subOpcode = (modrm >> 3) & 0x07;
	static const std::string shiftMnemonics[] = { "rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar" };
	currentInstruction->mnemonic = shiftMnemonics[subOpcode];
	bool is8Bit = !(opcode & 0x01);
	decodeModRM(is8Bit, true, true);
	if (0xD0 == (opcode & 0xFE))
	{
		currentInstruction->operands += ", 1";
	}
	else
	{
		currentInstruction->operands += ", cl";
	}
}

void X86Disassembler::decodeGroup4And5(uint8_t opcode)
{
	currentOffset++;
	uint8_t modrm = currentBuffer[currentOffset];
	uint8_t subOpcode = (modrm >> 3) & 0x07;
	bool is8Bit = (0xFE == opcode);
	switch (subOpcode)
	{
	case 0: currentInstruction->mnemonic = "inc"; break;
	case 1: currentInstruction->mnemonic = "dec"; break;
	case 2: currentInstruction->mnemonic = "call"; break;
	case 4: currentInstruction->mnemonic = "jmp"; break;
	case 6: currentInstruction->mnemonic = "push"; break;
	default: currentInstruction->mnemonic = "db"; break;
	}
	if ("db" != currentInstruction->mnemonic)
	{
		decodeModRM(is8Bit, true, true);
	}
	else
	{
		currentInstruction->operands = DisassemblerUtils::decToHexString(opcode) + " " +
			DisassemblerUtils::decToHexString(currentBuffer[currentOffset++]);
	}
}