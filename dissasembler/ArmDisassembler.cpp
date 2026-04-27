#include "ArmDisassembler.h"

Instruction ArmDisassembler::decodeNext(const uint8_t* buffer,
    size_t bufferLen, uint64_t virtualAddr)
{
    Instruction result;
    result.length = AARCH64_INSTRUCTION_LENGTH;
    result.bytes = std::vector<uint8_t>(buffer, buffer + AARCH64_INSTRUCTION_LENGTH);
    result.address = virtualAddr;
    result.isValid = true;

    currentInstruction = &result;

    if (bufferLen < AARCH64_INSTRUCTION_LENGTH) 
    {
        result.isValid = false;
        return result;
    }
    std::memcpy(&currentInstruction_bytes, buffer, AARCH64_INSTRUCTION_LENGTH);

    decodeInstruction();

    return result;
}


uint32_t ArmDisassembler::extractBits(uint8_t startBit, uint8_t length) const
{
    return (currentInstruction_bytes >> startBit) & ((1U << length) - 1);
}


int32_t ArmDisassembler::extractSignedBits(uint8_t startBit, uint8_t length)
{
    uint32_t raw = extractBits(startBit, length);
    uint32_t signBit = 1U << (length - 1);

    if (raw & signBit) 
    {
        return (int32_t)(raw | ~((1U << length) - 1));
    }
    return (int32_t)raw;
}

void ArmDisassembler::decodeInstruction()
{
    uint8_t instructionGroup = extractBits(25, 4);

    switch (instructionGroup)
    {
    case 0x8: case 0x9:
        decodeDataProcImm();
        break;

    case 0xA: case 0xB:
        decodeBranchSystem();
        break;

    case 0x4: case 0x6: case 0xC: case 0xE:
        decodeLoadStore();
        break;

    case 0x5: case 0xD: 
        decodeDataProcReg();
        break;

    default:
        currentInstruction->mnemonic = "<Undefind>"; 
        currentInstruction->isValid = false;
        break;
    }
}

void ArmDisassembler::decodeDataProcImm()
{
    uint8_t helper_bits = extractBits(23, 3);
    uint8_t sf = extractBits(31, 1);
    bool is64 = (sf == 1);

    if (helper_bits == 0x02) 
    {
        uint8_t rd = extractBits(0, 5);
        uint8_t rn = extractBits(5, 5);
        uint16_t imm = extractBits(10, 12);
        uint8_t op_s = extractBits(29, 2);

        switch (op_s) 
        {
            case 0: currentInstruction->mnemonic = "add";  break;
            case 1: currentInstruction->mnemonic = "adds"; break;
            case 2: currentInstruction->mnemonic = "sub";  break;
            case 3: currentInstruction->mnemonic = "subs"; break;
        }
        currentInstruction->operands = getRegName(rd, is64, true) + ", " +
            getRegName(rn, is64, true) + ", #" + std::to_string(imm);
    }
    else if (helper_bits == 0x04)
    {
        uint8_t rd = extractBits(0, 5);
        uint8_t rn = extractBits(5, 5);
        uint8_t opc = extractBits(29, 2); 

        switch (opc) {
        case 0: currentInstruction->mnemonic = "and";  break;
        case 1: currentInstruction->mnemonic = "orr";  break;
        case 2: currentInstruction->mnemonic = "eor";  break;
        case 3: currentInstruction->mnemonic = "ands"; break;
        }

        uint32_t immN = extractBits(22, 1);
        uint32_t immr = extractBits(16, 6);
        uint32_t imms = extractBits(10, 6);

        currentInstruction->operands = getRegName(rd, is64) + ", " +
            getRegName(rn, is64) + ", #<bitmask>";
    }
    else if (helper_bits == 0x05)
    {
        uint8_t rd = extractBits(0, 5);
        uint16_t imm16 = extractBits(5, 16);
        uint8_t hw = extractBits(21, 2);
        uint8_t opc = extractBits(29, 2);  

        switch (opc) 
        {
            case 0: currentInstruction->mnemonic = "movn"; break;
            case 2: currentInstruction->mnemonic = "movz"; break;
            case 3: currentInstruction->mnemonic = "movk"; break;
        }

        uint8_t shift = hw * 16;
        currentInstruction->operands = getRegName(rd, is64) + ", #" + std::to_string(imm16);
        if (shift > 0) currentInstruction->operands += ", lsl #" + std::to_string(shift);
    }
}

std::string ArmDisassembler::getRegName(uint8_t regIdx, bool is64Bit, bool preferSP)  const
{
    if (regIdx == 31)
    {
        if (preferSP) 
        {
            return is64Bit ? "sp" : "wsp"; 
        }
		return is64Bit ? "xzr" : "wzr";
    }
    return (is64Bit ? "x" : "w") + std::to_string(regIdx);
}

void ArmDisassembler::decodeBranchSystem()
{
    uint32_t op = extractBits(26, 6);

    if ((op & 0x1F) == 0x05) 
    {
        bool isLink = (extractBits(31, 1) == 1);
        currentInstruction->mnemonic = isLink ? "bl" : "b";

        int32_t offset = extractSignedBits(0, 26);
        uint64_t target = currentInstruction->address + (offset * 4);
        currentInstruction->operands = "0x" + DisassemblerUtils::decToHexString(target);
    }

    else if (extractBits(24, 8) == 0x54)
    {
        uint8_t cond = extractBits(0, 4);
        int32_t offset = extractSignedBits(5, 19);
        uint64_t target = currentInstruction->address + (offset * 4);

        const char* condNames[] = {
            "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
            "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
        };

        currentInstruction->mnemonic = std::string("b.") + condNames[cond];
        currentInstruction->operands = "0x" + DisassemblerUtils::decToHexString(target);
    }

    else if (extractBits(10, 22) == 0x3587C0) 
    {
        currentInstruction->mnemonic = "ret";
        uint8_t rn = extractBits(5, 5);
        currentInstruction->operands = (rn == 30) ? "" : getRegName(rn, true, false);
    }
}
void ArmDisassembler::decodeLoadStore()
{
    uint8_t size = extractBits(30, 2);
    uint8_t opc = extractBits(22, 2);
    uint8_t rn = extractBits(5, 5); 
    uint8_t rt = extractBits(0, 5);  

    uint16_t imm12 = extractBits(10, 12);

    bool isLoad = (extractBits(22, 1) == 1);
    currentInstruction->mnemonic = isLoad ? "ldr" : "str";

    uint32_t offset = imm12 << size;

    bool is64 = (size == 3);
    currentInstruction->operands = getRegName(rt, is64,false) + ", [" +
        getRegName(rn, true, true) + ", #" +
        std::to_string(offset) + "]";
}


void ArmDisassembler::decodeDataProcReg()
{
    uint8_t rd = extractBits(0, 5);
    uint8_t rn = extractBits(5, 5);
    uint8_t rm = extractBits(16, 5);
    uint8_t op_s = extractBits(29, 2);
    uint8_t sf = extractBits(31, 1);

    bool is64 = (sf == 1);

    switch (op_s) 
    {
        case 0: currentInstruction->mnemonic = "add";  break;
        case 1: currentInstruction->mnemonic = "adds"; break;
        case 2: currentInstruction->mnemonic = "sub";  break;
        case 3: currentInstruction->mnemonic = "subs"; break;
    }

    currentInstruction->operands = getRegName(rd, is64) + ", " +
        getRegName(rn, is64) + ", " +
        getRegName(rm, is64);
}