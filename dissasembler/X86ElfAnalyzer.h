#pragma once
#include "ElfAnalyzer.h"

#define STRINGS_SAME 0
#define TEXT_SECTION_NAME ".text"

class X86ElfAnalyzer : public ElfAnalyzer 
{
protected:
    virtual bool findTextSection(const std::vector<uint8_t>& buffer, 
        uint64_t& offset, uint64_t& size, uint64_t& vaddr) override;
};