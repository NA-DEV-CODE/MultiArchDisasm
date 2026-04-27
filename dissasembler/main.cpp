#include <iostream>
#include <memory>
#include "ArchiDetector.h"
#include "X86Disassembler.h"
#include "ArmDisassembler.h"
#include "X86ElfAnalyzer.h"
#include "ArmElfAnalyzer.h"

#define NUM_OF_VALID_ARGS 2
#define PATH_ARG_INDEX 1
#define ERROR_EXIT_CODE 1

int main(int argc, char* argv[]) 
{
    if (argc < NUM_OF_VALID_ARGS) 
    {
        return ERROR_EXIT_CODE; 
    }

    std::string path = argv[PATH_ARG_INDEX];
    Architecture arch;

    try 
    {
        arch = ArchiDetector::detectArchitecture(path);
    }
    catch (...)
    {
        return ERROR_EXIT_CODE;
    }

    std::unique_ptr<Disassembler> disasm;
    std::unique_ptr<ElfAnalyzer> analyzer;

    if (Architecture::X86_32 == arch) 
    {
        disasm = std::make_unique<X86Disassembler>();
        analyzer = std::make_unique<X86ElfAnalyzer>();
    }
    else if (Architecture::ARM_32 == arch) 
    {
        disasm = std::make_unique<ArmDisassembler>();
        analyzer = std::make_unique<ArmElfAnalyzer>();
    }
    else 
    {
        return ERROR_EXIT_CODE;
    }
    analyzer->analyze(path, disasm.get());

    return 0;
}