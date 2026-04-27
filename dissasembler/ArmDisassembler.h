#pragma once

#include "Disassembler.h"
#include "DisassemblerUtils.h"
#include <cstring>

#define AARCH64_INSTRUCTION_LENGTH 4

class ArmDisassembler : public Disassembler
{
private:
    void decodeInstruction();
    void decodeDataProcImm();
    void decodeDataProcReg();
    void decodeLoadStore();
    void decodeBranchSystem();
    std::string getRegName(uint8_t regIdx, bool is64BitRegister, bool preferSP=false) const;
    int64_t extractSignedImm(uint8_t startBit, uint8_t length);
    uint32_t extractBits(uint8_t startBit, uint8_t length) const;
    int32_t extractSignedBits(uint8_t startBit, uint8_t length);

    uint32_t currentInstruction_bytes;
    Instruction* currentInstruction;

public:
    ArmDisassembler() = default;
    ~ArmDisassembler() = default;
    virtual Instruction decodeNext(const uint8_t* buffer, 
        size_t bufferLen, uint64_t virtualAddr) override;
};