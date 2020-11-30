#!/usr/bin/env python
# coding: utf-8

import os.path
import struct
import re
from binaryninja import * 

morestack_noctxt_sym = None
slicebytetostring_sym = None
morestack_noctxt = None
slicebytetostring = None

def handle_deref(bv, deref_size, deref_addr):
    br = binaryninja.BinaryReader(bv)
    br.seek(deref_addr)
    data = br.read(deref_size)
    return data

class EmuMagic(object):

    def _get_struct_fmt(self, size, signed):
        fmt = self.structfmt[size]
        if signed:
            fmt = fmt.lower()
        return (
            '<' if self.arch.endianness == binaryninja.Endianness.LittleEndian
            else ''
        ) + fmt
    
    def read_memory(self, location, size):
        # TODO: Implement virtual memory? - this works for now :shrug:
        for segment in self.bv.segments:
            if location >= segment.start and location <= segment.end:
                #print(hex(struct.unpack(self._get_struct_fmt(size, False), self.bv.read(location, size))[0]))
                return struct.unpack(self._get_struct_fmt(size, False), self.bv.read(location, size))[0]

        result = struct.unpack(self._get_struct_fmt(size, False), self.memory[location:location+size])[0]
        return result
    
    def write_memory(self, addr, size, value):
        signed = value < 0
        if size <= 8:
            d = struct.pack(self._get_struct_fmt(size, signed), value)
            self.memory[addr:addr+size] = d
        else:
            self.write_memory(addr, 8, (value >> 0) % 2**64)
            self.write_memory(addr + 8, 8, (value >> 64) % 2**64)

    def set_register(self, inst, value):
        register_name = inst.dest.name
        register_info = self.arch.regs[register_name]
        # Are we setting a partial register or the full width one?
        if register_name == register_info.full_width_reg:
            self.registers[register_name] = value
            return value

        # from https://github.com/joshwatshttps://github.com/joshwatson/emilator/blob/master/emilator.py#L139-L148on/emilator/blob/master/emilator.py#L139-L148
        # mask off the value that will be replaced
        full_width_reg_info = self.arch.regs[register_info.full_width_reg]
        full_width_reg_value = self.registers[full_width_reg_info.full_width_reg]

        # https://reverseengineering.stackexchange.com/a/14610
        # 32 bit ops will clear the top 32 bits
        if register_info.extend == binaryninja.ImplicitRegisterExtend.ZeroExtendToFullWidth:
            full_width_reg_value = value
        elif register_info.extend == binaryninja.ImplicitRegisterExtend.NoExtend:
            # mask off the value that will be replaced
            mask = (1 << register_info.size * 8) - 1
            full_mask = (1 << full_width_reg_info.size * 8) - 1
            reg_bits = mask << (register_info.offset * 8)

            full_width_reg_value &= full_mask ^ reg_bits
            full_width_reg_value |= value << register_info.offset * 8

        self.registers[register_info.full_width_reg] = full_width_reg_value
        return value

    def print_registers(self, prefix):
        log_debug(f"{prefix} | {self.registers}")

    def handle_LLIL_XOR(self, inst):
        left = self.handle(inst.left)
        right = self.handle(inst.right)
        log_debug("Degobfuscate: XOR " + chr(left ^ right))
        self.output += chr(left ^ right)
        return left ^ right
    
    def handle_LLIL_ZX(self, expr):
        return self.handle(expr.src)
    
    def handle_LLIL_GOTO(self, expr):
        self.ip = expr.dest
    
    def handle_LLIL_STORE(self, inst):
        addr = self.handle(inst.dest)
        value = self.handle(inst.src)
        self.write_memory(addr, inst.size, value)

    # Signed less than
    def handle_LLIL_CMP_SLT(self, inst):
        left = self.handle(inst.left)
        right = self.handle(inst.right)
        return left < right
        
    # Unsigned less than or equal
    def handle_LLIL_CMP_ULE(self, inst):
        left = int(self.handle(inst.left))
        right = int(self.handle(inst.right))
        return left <= right
    
    def handle_LLIL_IF(self, expr):
        res = self.handle(expr.condition)
        if res:
            self.ip = expr.true
        else:
            self.ip = expr.false
    
    def handle_LLIL_LOAD(self, inst):
        value = self.handle(inst.src)
        return self.read_memory(value, inst.size)

    def handle_LLIL_SET_REG(self, inst):
        src = self.handle(inst.src)
        self.set_register(inst, src)
        return True
    
    def handle_LLIL_CONST(self, inst):
        return inst.constant

    def handle_LLIL_CONST_PTR(self, inst):
        return inst.constant

    def handle_LLIL_REG(self, inst):
        register_name = inst.src.name
        register_info = self.arch.regs[register_name]
        full_width_reg_info = self.arch.regs[register_info.full_width_reg]
        full_reg_value = self.registers[register_info.full_width_reg]

        mask = (1 << register_info.size * 8) - 1

        if inst.src == register_info.full_width_reg:
            return full_reg_value & mask

        mask = (1 << register_info.size * 8) - 1
        reg_bits = mask << (register_info.offset * 8)
        reg_value = (full_reg_value & reg_bits) >> (register_info.offset * 8)
        return reg_value
    
    def handle_LLIL_SUB(self, inst):
        return self.handle(inst.left) - self.handle(inst.right)

    def handle_LLIL_ADD(self, inst):
        return self.handle(inst.left) + self.handle(inst.right)

    def handle(self, inst):
        log_debug(f"Degobfuscate executing: {inst.operation.name}")
        for field in LowLevelILInstruction.ILOperations[inst.operation]:
            handler = f"handle_{inst.operation.name}"
            has_handler = hasattr(self, handler)
            if has_handler is False:
                log_debug(f"Degobfuscate implement: {inst.operation.name}")
                return None
            else:
                res = getattr(self, handler)(inst)
                return res
    
    def execute(self):
        if self.ip >= len(self.instructions):
            return False
        log_debug(f"Degobfuscate IP: {self.ip}")
        instr = self.instructions[self.ip]
        self.candidate.set_auto_instr_highlight(instr.address, binaryninja.enums.HighlightStandardColor.GreenHighlightColor)
        self.ip += 1
        self.handle(instr)
        return True
    
    def run(self):
        while True:
            if not self.execute():
                break
    
    def __init__(self, bv, candidate):
        self.bv = bv
        self.candidate = candidate
        self.arch = candidate.arch
        self.instructions = candidate.llil
        self.ip = 0
        self.output=""

        self.registers = {}
        for r in self.arch.regs:
            reg = self.arch.regs[r]
            if reg.full_width_reg == r:
                self.registers[r] = 0

        self.memory = bytearray('\x00', encoding='ascii')*10000000
        self.stack = []

        #TODO: Remove arch specific code
        # https://www.reddit.com/r/golang/comments/gq4pfh/what_is_the_purpose_of_fs_and_gs_registers_in/
        # rcx = [fsbase - 8].q
        # if (rsp u<= [rcx + 0x10].q) then 2 @ 0x6aec49 else 4 @ 0x6aebb3
        self.memory[92] = 0
        self.registers["fsbase"] = 100
        self.registers["rsp"] = 500
        
        self.structfmt = {1: 'B', 2: 'H', 4: 'L', 8: 'Q', 16: 'QQ'}

def findslice(bv):
    global morestack_noctxt_sym
    global slicebytetostring_sym
    global morestack_noctxt
    global slicebytetostring
    morestack_noctxt_sym = bv.get_symbols_by_name("runtime.morestack_noctxt") or bv.get_symbols_by_name("_runtime.morestack_noctxt") or bv.get_symbols_by_name("runtime_morestack_noctxt") or bv.get_symbols_by_name("_runtime_morestack_noctxt")
    slicebytetostring_sym = bv.get_symbols_by_name("runtime.slicebytetostring") or bv.get_symbols_by_name("_runtime.slicebytetostring") or bv.get_symbols_by_name("runtime_slicebytetostring") or bv.get_symbols_by_name("_runtime_slicebytetostring")
    morestack_noctxt = bv.get_function_at(morestack_noctxt_sym[0].address)
    slicebytetostring = bv.get_function_at(slicebytetostring_sym[0].address)

def validfunc(func):
    #Disabling this until it's integrated into the deobfuscation plugin since the symbols will not be auto
    #if func.symbol.auto == False:
        #return False
    if {morestack_noctxt, slicebytetostring} != set(func.callees):
        return False
    def findxor(expr):
        if expr.operation == LowLevelILOperation.LLIL_XOR:
            return True
        for field in LowLevelILInstruction.ILOperations[expr.operation]:
            if field[1] == "expr":
                if findxor(getattr(expr, field[0])):
                    return True
        return False

    foundxor = False
    for il in func.llil.instructions:
        if findxor(il):
            foundxor = True
    return foundxor

def nextname(bv, newname):
    for x in range(1,10000):
        candidate = f"{newname}_{x}"
        if candidate in bv.symbols.keys():
            continue
        return candidate

def deobfunc(bv, func):
    if not slicebytetostring:
        findslice(bv)
    log_info(f"Degobfuscate analyzing {func.name}")
    emu = EmuMagic(bv, func)
    emu.run()
    if emu.output != "":
        log_info(f"Result: {emu.output}")
        pattern = re.compile(r'[\W_]+')
        shortname = pattern.sub("", emu.output)[0:32]
        if len(emu.output) > 32 or shortname != emu.output[0:32]:
            shortname += "..."
            for xref in bv.get_code_refs(func.start):
                xref.function.set_comment_at(xref.address, emu.output)
        newname = "str_" + shortname #TODO: create setting
        if newname in bv.symbols.keys() and func.start != bv.symbols[newname].address:
            newname = nextname(bv, newname)
        func.name = newname

def deob(bv):
    if not slicebytetostring:
        findslice(bv)

    log_info(f"Degobfuscate checking {len(bv.functions)} total functions")
    counter = 0

    for func in bv.functions:
        if validfunc(func):
            counter += 1
            deobfunc(bv, func)

    log_info(f"Degobfuscate successfully analyzed {counter} functions")

def deobsingle(bv, func):
    if not slicebytetostring:
        findslice(bv)
    if validfunc(func):
        deobfunc(bv, func)
    else:
        log_warn(f"Degobfuscate: {func.name} is not a valid candidate function")

PluginCommand.register_for_function("Degobfuscate this function", "Tries to just deobfuscate this function as a gobfuscated string", deobsingle)
PluginCommand.register("Degobfuscate all strings", "Searches all functions for obfuscated xor strings and attempts light IL emulation to recover them.", deob)
