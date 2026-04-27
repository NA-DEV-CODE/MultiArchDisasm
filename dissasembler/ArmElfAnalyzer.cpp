#include "ArmElfAnalyzer.h"
#include <cstring>

bool ArmElfAnalyzer::findTextSection(const std::vector<uint8_t>& buffer,
    uint64_t& offset, uint64_t& size, uint64_t& vaddr)
{
    uint64_t shoff;
    uint16_t shentsize, shnum, shstrndx;

    std::memcpy(&shoff, &buffer[ELF64_SH_OFFSET], sizeof(uint64_t));
    std::memcpy(&shentsize, &buffer[ELF64_SH_ENTSIZE], sizeof(uint16_t));
    std::memcpy(&shnum, &buffer[ELF64_SH_NUM], sizeof(uint16_t));
    std::memcpy(&shstrndx, &buffer[ELF64_SH_STRNDX], sizeof(uint16_t));

    uint64_t strTableEntry = shoff + (shstrndx * shentsize);
    uint64_t strTableOffset;
    std::memcpy(&strTableOffset, &buffer[strTableEntry + ELF64_STRTAB_OFFSET], sizeof(uint64_t));

    for (uint16_t i = 0; i < shnum; i++)
    {
        uint64_t entry = shoff + (i * shentsize);
        uint32_t nameIdx;
        std::memcpy(&nameIdx, &buffer[entry], sizeof(uint32_t));

        const char* name = (const char*)&buffer[strTableOffset + nameIdx];

        if (STRINGS_SAME == std::strcmp(name, TEXT_SECTION_NAME))
        {
            std::memcpy(&vaddr, &buffer[entry + ELF64_SH_ENTRY_ADDR], sizeof(uint64_t));
            std::memcpy(&offset, &buffer[entry + ELF64_SH_ENTRY_OFFSET], sizeof(uint64_t));
            std::memcpy(&size, &buffer[entry + ELF64_SH_ENTRY_SIZE], sizeof(uint64_t));
            return true;
        }
    }
    return false;
}