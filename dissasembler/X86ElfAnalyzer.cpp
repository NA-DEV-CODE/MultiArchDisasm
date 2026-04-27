#include "X86ElfAnalyzer.h"
#include <cstring>

bool X86ElfAnalyzer::findTextSection(const std::vector<uint8_t>& buffer,
    uint64_t& offset, uint64_t& size, uint64_t& vaddr) 
{
    uint32_t shoff;
    uint16_t shentsize, shnum, shstrndx;

    std::memcpy(&shoff, &buffer[ELF32_SH_OFFSET], sizeof(uint32_t));
    std::memcpy(&shentsize, &buffer[ELF32_SH_ENTSIZE], sizeof(uint16_t));
    std::memcpy(&shnum, &buffer[ELF32_SH_NUM], sizeof(uint16_t));
    std::memcpy(&shstrndx, &buffer[ELF32_SH_STRNDX], sizeof(uint16_t));

    uint32_t strTableEntry = shoff + (shstrndx * shentsize);
    uint32_t strTableOffset;
    std::memcpy(&strTableOffset, &buffer[strTableEntry + ELF32_STRTAB_OFFSET], sizeof(uint32_t));

    for (uint16_t i = 0; i < shnum; i++) 
    {
        uint32_t entry = shoff + (i * shentsize);
        uint32_t nameIdx;
        std::memcpy(&nameIdx, &buffer[entry], sizeof(uint32_t));

        const char* name = (const char*)&buffer[strTableOffset + nameIdx];

        if (STRINGS_SAME == std::strcmp(name, TEXT_SECTION_NAME)) 
        {
            uint32_t tempAddr, tempOffset, tempSize;
            std::memcpy(&tempAddr, &buffer[entry + ELF32_SH_ENTRY_ADDR], sizeof(uint32_t));
            std::memcpy(&tempOffset, &buffer[entry + ELF32_SH_ENTRY_OFFSET], sizeof(uint32_t));
            std::memcpy(&tempSize, &buffer[entry + ELF32_SH_ENTRY_SIZE], sizeof(uint32_t));

            vaddr = tempAddr;
            offset = tempOffset;
            size = tempSize;
            return true;
        }
    }
    return false;
}