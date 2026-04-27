#pragma once

#include "Disassembler.h"
#include "DisassemblerUtils.h"
#include <cstring>

#define REGISTERS_NUM 8
#define MODE_ADD_BYTE 1
#define MODE_ADD_DWORD 2
#define MODE_2_REGISTERS 0b11
#define MODE_SIB 0b100
#define MODE_RM_DISPLACEMENT 0b101
#define RI_MODE 0
#define ESP_CODE 0b100

enum PrefixValues : uint8_t {
    // Group 1: Lock and Repeat Prefixes
    PRE_LOCK = 0xF0,
    PRE_REPNE = 0xF2, // ощощ вн л-REPNZ
    PRE_REPE = 0xF3, // ощощ вн л-REP ае REPZ

    // Group 2: Segment Override Prefixes
    PRE_CS_OVERRIDE = 0x2E,
    PRE_SS_OVERRIDE = 0x36,
    PRE_DS_OVERRIDE = 0x3E,
    PRE_ES_OVERRIDE = 0x26,
    PRE_FS_OVERRIDE = 0x64,
    PRE_GS_OVERRIDE = 0x65,

    // Group 3: Operand-Size Override
    PRE_OPERAND_SIZE = 0x66,

    // Group 4: Address-Size Override
    PRE_ADDRESS_SIZE = 0x67
};

static const std::string shortJccs[] = 
{ "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
"js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg" 
};

static const std::string jccMnemonics[] = 
{
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
};

class X86Disassembler : public Disassembler
{
	public:
	virtual Instruction decodeNext(const uint8_t* buffer, size_t bufferLen, uint64_t virtualAddr) override;
	
private:
	void decodePrefixes();
	void decodeOpcode();
    void decodeModRM(const bool is8Bit, const bool regIsDest, bool oneOperandOnly);
    void decodeTwoByteOpcode();
	std::string getRegisterName(uint8_t regIndex, const bool is8Bit);
    void decodeStandardArithmetic(uint8_t opcode);
	void decodeImmediateToAccumulator(uint8_t opcode);
    void decodeCall();
	void decodeGroup1();
	void decodeGroup2(uint8_t opcode);
    void decodeGroup3(uint8_t opcode);
	void decodeGroup4And5(uint8_t opcode);
    void decodeShortRelative();
    void decodeMoveRegImm(uint8_t opcode);
    void decodeArithmeticImmediate(uint8_t opcode);
    void decodeMoveMemImm(uint8_t opcode);
	void decodeRet();


	std::string getSegmentOverridePrefix();
	const uint8_t* currentBuffer;
	size_t currentOffset;
	size_t maxLen;
    Instruction* currentInstruction;

	static constexpr bool checkIsPrefix(uint8_t b) {
		return (b == PRE_LOCK || b == PRE_REPNE || b == PRE_REPE ||
			b == PRE_CS_OVERRIDE || b == PRE_SS_OVERRIDE || b == PRE_DS_OVERRIDE || b == PRE_ES_OVERRIDE || b == PRE_FS_OVERRIDE || b == PRE_GS_OVERRIDE ||
			b == PRE_OPERAND_SIZE || b == PRE_ADDRESS_SIZE);} 
    
    struct
    {
        uint8_t lockRep;
        uint8_t segmentOverride;
        bool hasOpSizeOverride;
        bool hasAddrSizeOverride;
    } activePrefixes;
           
};