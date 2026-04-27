#pragma once

#include "ElfDefines.h"
#include <string>
#include <vector>
#include <fstream>
#include "Disassembler.h"

class ElfAnalyzer {
public:
    virtual ~ElfAnalyzer() = default;
    void analyze(const std::string& filePath, Disassembler* disasm);

protected:
    virtual bool findTextSection(const std::vector<uint8_t>& buffer, uint64_t& offset, uint64_t& size, uint64_t& vaddr) = 0;
};

