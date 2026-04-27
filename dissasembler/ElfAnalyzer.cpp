#include "ElfAnalyzer.h"
#include <iostream>

void ElfAnalyzer::analyze(const std::string& filePath, Disassembler* disasm)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open())
    {
        return;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    uint64_t codeOffset = 0, codeSize = 0, virtualAddr = 0;

    if (!findTextSection(buffer, codeOffset, codeSize, virtualAddr))
    {
        return;
    }

    size_t currentPos = 0;
    while (currentPos < codeSize)
    {
        Instruction instr = disasm->decodeNext(buffer.data() + codeOffset + currentPos,
            codeSize - currentPos, virtualAddr + currentPos);

        if (!instr.isValid)
        {
            break;
        }

        printf("0x%016llX:  %-12s %s\n", instr.address, instr.mnemonic.c_str(), instr.operands.c_str());
        currentPos += instr.length;
    }
}