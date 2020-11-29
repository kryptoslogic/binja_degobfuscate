#!/usr/bin/env python
# coding: utf-8

import os.path
import struct
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
    # "instruction pointer"
    ip = 0
    instructions = None
    
    # What endianness does our arch use
    endianness = None

    #TODO: Remove arch specific code
    registers = {
        "fsbase": 100,
        "rcx": 0,
        "rsp": 0,
        "rax": 0,
        "rbp": 0,
        "cl": 0,
    }
    memory = bytearray('\x00', encoding='ascii')*10000000
    stack = []

    # https://www.reddit.com/r/golang/comments/gq4pfh/what_is_the_purpose_of_fs_and_gs_registers_in/
    # rcx = [fsbase - 8].q
    # if (rsp u<= [rcx + 0x10].q) then 2 @ 0x6aec49 else 4 @ 0x6aebb3
    memory[92] = 0
    registers["rsp"] = 500
    
    structfmt = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
    def _get_struct_fmt(self, size):
        return (
            '<' if self.endianness == binaryninja.Endianness.LittleEndian
            else ''
        ) + self.structfmt[size]
    
    def read_memory(self, location, size):
        result = struct.unpack(self._get_struct_fmt(size), self.memory[location:location+size])[0]
        return result
    
    def write_memory(self, addr, size, value):
        d = struct.pack(self._get_struct_fmt(size), value)
        self.memory[addr:addr+size] = d

    def handle_LLIL_XOR(self, inst):
        left = self.handle(inst.left)
        right = self.handle(inst.right)
        log_info("Degobfuscate: XOR " + chr(left ^ right))
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
        reg_name = str(inst.dest)
        self.registers[reg_name] = src
        log_debug(f"Degobfuscate: {reg_name}={hex(src)}")
        return True
    
    def handle_LLIL_CONST(self, inst):
        return(inst.value.value)
            
    def handle_LLIL_REG(self, inst):
        reg_name = str(inst)
        return self.registers[reg_name]
    
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
                log_info(f"Degobfuscate implement: {inst.operation.name}")
                return None
            else:
                res = getattr(self, handler)(inst)
                return res
    
    def execute(self):
        if self.ip >= len(self.instructions):
            return False
        log_debug(f"Degobfuscate IP: {hex(self.ip)}")
        instr = self.instructions[self.ip]
        self.ip += 1
        self.handle(instr)
        return True
    
    def run(self):
        while True:
            if not self.execute():
                break
    
    def __init__(self, candidate):
        self.endianness = candidate.arch.endianness
        self.instructions = candidate.llil

def findslice(bv):
    global morestack_noctxt_sym
    global slicebytetostring_sym
    global morestack_noctxt
    global slicebytetostring
    morestack_noctxt_sym = bv.get_symbols_by_name("runtime.morestack_noctxt") or bv.get_symbols_by_name("_runtime.morestack_noctxt") or bv.get_symbols_by_name("runtime_morestack_noctxt") or bv.get_symbols_by_name("_runtime_morestack_noctxt")
    slicebytetostring_sym = bv.get_symbols_by_name("runtime.slicebytetostring") or bv.get_symbols_by_name("_runtime.slicebytetostring") or bv.get_symbols_by_name("runtime_slicebytetostring") or bv.get_symbols_by_name("_runtime_slicebytetostring")
    morestack_noctxt = bv.get_function_at(morestack_noctxt_sym[0].address)
    slicebytetostring = bv.get_function_at(slicebytetostring_sym[0].address)


def deobfunc(bv, func):
    if not slicebytetostring:
        findslice(bv)
    emu = EmuMagic(func)
    log_info(f"Degobfuscate analyzing {func.name}")
    emu.run()


def deob(bv):
    findslice(bv)
    deobfuscate_candidates = set()

    log_info(f"Degobfuscate {len(bv.functions)} total functions")

    for func in bv.functions:
        func_callees = func.callees
        if (len(func_callees)) == 2:
            if morestack_noctxt in func_callees and slicebytetostring in func_callees:
                log_info(func.name)
                for ins in func.instructions:
                    ins_type = ins[0][0]
                    if ins_type.text != "xor": #TODO: Remove arch specific code
                        continue
                    src = ins[0][2]
                    dst  = ins[0][4]
                    if src == "eax" and dst == "eax": #TODO: Remove arch specific code
                        continue
                    
                    deobfuscate_candidates.add(func)
                    break

    for candidate in deobfuscate_candidates:
        deobfunc(bv, f)

PluginCommand.register_for_function("Degobfuscate function strings", "Searches Symgrate2 db for the current function.", deobfunc)
PluginCommand.register("Degobfuscate all strings", "Searches all functions for obfuscated xor strings and attempts light IL emulation to recover them.", deob)
