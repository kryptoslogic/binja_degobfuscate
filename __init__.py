#!/usr/bin/env python
# coding: utf-8

import os.path
import struct
import re
from binaryninja import * 

function_name_regex = re.compile(r'[\W_]+')
Settings().register_group("degobfuscate", "DeGObfuscate")
Settings().register_setting("degobfuscate.prefix", """
    {
        "title" : "Default function prefix",
        "type" : "string",
        "default" : "str_",
        "description" : "The string prefix that will be put in front of a shortened string name for deobfuscated functions."
    }
    """)
Settings().register_setting("degobfuscate.maxlength", """
    {
        "title" : "Maximum Length",
        "type" : "number",
        "default" : 32,
        "description" : "The maimum string length before the de-obfuscated string will be truncated when used in renaming the function. String comments will be added if the string is truncated."
    }
    """)
Settings().register_setting("degobfuscate.highlight", """
    {
        "title" : "Debug Highlights",
        "type" : "boolean",
        "default" : false,
        "description" : "Whether or not to add highlights to emulated code, useful for debugging the emulation."
    }
    """)

def handle_deref(bv, deref_size, deref_addr):
    br = BinaryReader(bv)
    br.seek(deref_addr)
    data = br.read(deref_size)
    return data

class EmuMagic(object):

    def _get_struct_fmt(self, size, signed):
        fmt = self.structfmt[size]
        if signed:
            fmt = fmt.lower()
        return (
            '<' if self.arch.endianness == Endianness.LittleEndian
            else ''
        ) + fmt
    
    def read_memory(self, location, size):
        def get_data(addr, size):
            for segment in self.bv.segments:
                if addr >= segment.start and addr <= segment.end:
                    log_debug(f"READING {size} BYTES FROM SEGMENT @ {addr}")
                    return self.bv.read(addr, size)
            return self.memory[addr:addr+size]

        if size <= 8:
            return struct.unpack(self._get_struct_fmt(size, False), get_data(location, size))[0]
        else:
            if size != 16:
                raise Exception("TODO: Fix reads of size 16 bytes+")
                
            a = struct.unpack(self._get_struct_fmt(8, False), get_data(location, 8))[0]
            b = struct.unpack(self._get_struct_fmt(8, False), get_data(location + 8, 8))[0]
            return (b << 64) + a
    
    def write_memory(self, addr, size, value):
        signed = value < 0
        if size <= 8:
            d = struct.pack(self._get_struct_fmt(size, signed), value)
            self.memory[addr:addr+size] = d
        else:
            if size != 16:
                raise Exception("TODO: Fix reads of size 16 bytes+")
            self.write_memory(addr, 8, (value >> 0) % 2**64)
            self.write_memory(addr + 8, 8, (value >> 64) % 2**64)

    def set_register(self, inst, value):
        register_name = inst.dest.name
        register_info = self.arch.regs[register_name]
        # Are we setting a partial register or the full width one?
        if register_name == register_info.full_width_reg:
            self.registers[register_name] = value
            return value

        # from https://github.com/joshwatson/emilator/blob/master/emilator.py#L139-L148on/emilator/blob/master/emilator.py#L139-L148
        # mask off the value that will be replaced
        full_width_reg_info = self.arch.regs[register_info.full_width_reg]
        full_width_reg_value = self.registers[full_width_reg_info.full_width_reg]

        # https://reverseengineering.stackexchange.com/a/14610
        # 32 bit ops will clear the top 32 bits
        if register_info.extend == ImplicitRegisterExtend.ZeroExtendToFullWidth:
            full_width_reg_value = value
        elif register_info.extend == ImplicitRegisterExtend.NoExtend:
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

    # Pop a value from the stack
    def stack_pop(self, size):
        sp = self.arch.stack_pointer
        self.registers[sp] += size
        return self.read_memory(self.registers[sp], size)

    # Push a value onto the stack
    def stack_push(self, value, size):
        sp = self.arch.stack_pointer
        self.write_memory(self.registers[sp], size, value)
        self.registers[sp] -= size
        return self.registers[sp]

    def handle_LLIL_TAILCALL(self, expr):
        callee = self.handle(expr.dest)
        callee_func = self.bv.get_function_at(callee)
        log_debug(f"LLIL_TAILCALL: We're jumping to {callee_func.name}")
        self.instructions = callee_func.llil
        self.ip = 0

    def handle_LLIL_CALL(self, expr):
        callee = self.handle(expr.dest)
        callee_func = self.bv.get_function_at(callee)

        slicebytetostring_sym = self.bv.get_symbols_by_name("runtime.slicebytetostring") or self.bv.get_symbols_by_name("_runtime.slicebytetostring") or self.bv.get_symbols_by_name("runtime_slicebytetostring") or self.bv.get_symbols_by_name("_runtime_slicebytetostring")
        slicebytetostring = self.bv.get_function_at(slicebytetostring_sym[0].address)
        if callee_func == slicebytetostring:
            log_debug("LLIL_CALL: Avoiding call to runtime function, we are out of here!")
            # Setting the IP to overflow the available instructions to halt execution
            self.ip = len(self.instructions) + 1
            return
        ret_address = self.instructions[self.ip + 1].address
        log_debug(f"LLIL_CALL: We're jumping to {callee_func.name} and we'll come back to {hex(ret_address)}")
        self.stack_push(ret_address, self.arch.address_size)
        self.instructions = callee_func.llil
        self.ip = 0

    def handle_LLIL_RET(self, expr):
        ret_addr = self.stack_pop(self.arch.address_size)
        ret_func = self.bv.get_functions_containing(ret_addr)[0]
        self.instructions = ret_func.llil
        ret_il = ret_func.get_low_level_il_at(ret_addr)
        self.ip = ret_il.instr_index
        log_debug(f"LLIL_RET: Returning to {ret_func.name} @ {hex(ret_addr)} and IP is becoming: {self.ip}")

    def handle_LLIL_PUSH(self, expr):
        return self.stack_push(self.handle(expr.src), expr.size)

    def handle_LLIL_POP(self, expr):
        return self.stack_pop(expr.size)

    def handle_LLIL_XOR(self, inst):
        left = self.handle(inst.left)
        right = self.handle(inst.right)
        log_debug("DeGObfuscate: XOR " + chr(left ^ right))
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
        log_debug(f"DeGObfuscate executing: {inst.operation.name}")
        for field in LowLevelILInstruction.ILOperations[inst.operation]:
            handler = f"handle_{inst.operation.name}"
            has_handler = hasattr(self, handler)
            if has_handler is False:
                log_debug(f"DeGObfuscate implement: {inst.operation.name}")
                return None
            else:
                res = getattr(self, handler)(inst)
                return res
    
    def execute(self):
        if self.ip >= len(self.instructions):
            return False
        log_debug(f"DeGObfuscate IP: {self.ip}")
        instr = self.instructions[self.ip]
        if self.highlight:
            self.candidate.set_auto_instr_highlight(instr.address, enums.HighlightStandardColor.GreenHighlightColor)
        self.ip += 1
        self.handle(instr)
        return True
    
    def run(self):
        while True:
            if not self.execute():
                break
        return self.output
    
    def __init__(self, bv, candidate):
        self.bv = bv
        self.candidate = candidate
        self.arch = candidate.arch
        self.instructions = candidate.llil
        self.ip = 0
        self.output = ""

        self.registers = {}
        for r in self.arch.regs:
            reg = self.arch.regs[r]
            if reg.full_width_reg == r:
                self.registers[r] = 0

        self.memory = bytearray('\x00', encoding='ascii')*10000000
        self.stack = []

        # TODO: Test on non-x86/x64
        # https://www.reddit.com/r/golang/comments/gq4pfh/what_is_the_purpose_of_fs_and_gs_registers_in/
        # rcx = [fsbase - 8].q
        # if (rsp u<= [rcx + 0x10].q) then 2 @ 0x6aec49 else 4 @ 0x6aebb3
        self.memory[92] = 0
        if bv.arch in [Architecture['x86'], Architecture['x86_64']]:
            self.registers["fsbase"] = 100
            self.registers["gsbase"] = 100
        self.registers[bv.arch.stack_pointer] = 0x10000
        self.structfmt = {1: 'B', 2: 'H', 4: 'L', 8: 'Q', 16: 'QQ'}

        self.highlight = Settings().get_bool("degobfuscate.highlight")


def validfunc(bv, func):
    morestack_noctxt_sym = bv.get_symbols_by_name("runtime.morestack_noctxt") or bv.get_symbols_by_name("_runtime.morestack_noctxt") or bv.get_symbols_by_name("runtime_morestack_noctxt") or bv.get_symbols_by_name("_runtime_morestack_noctxt")
    slicebytetostring_sym = bv.get_symbols_by_name("runtime.slicebytetostring") or bv.get_symbols_by_name("_runtime.slicebytetostring") or bv.get_symbols_by_name("runtime_slicebytetostring") or bv.get_symbols_by_name("_runtime_slicebytetostring")
    morestack_noctxt = bv.get_function_at(morestack_noctxt_sym[0].address)
    slicebytetostring = bv.get_function_at(slicebytetostring_sym[0].address)
    # TODO: Replace this with a much more robust heuristic for detecting obfuscated functions
    if not slicebytetostring in func.callees or not morestack_noctxt in func.callees:
        return False

    # Find functions which make use of an XOR primitive
    # Because we're using IL here we don't need to worry about xor eax, eax because that gets optimized into:
    # LLIL_SET_REG eax/LLIL_CONST 0
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
    
    if not foundxor:
        log_debug(f"{func.name} is not valid due to no usage of LLIL_XOR")
    return foundxor

def nextname(bv, newname):
    for x in range(1,10000):
        candidate = f"{newname}_{x}"
        if candidate in bv.symbols.keys():
            continue
        return candidate

def deobfunc(bv, func):
    emu = EmuMagic(bv, func)
    result = emu.run()
    if result != "":
        log_debug(f"DeGObfuscate result: {repr(result)}")
        maxlength = Settings().get_integer("degobfuscate.maxlength")
        shortname = function_name_regex.sub("", result)[0:maxlength]
        if shortname != result[0:maxlength]:
            for xref in bv.get_code_refs(func.start):
                xref.function.set_comment_at(xref.address, repr(result)[1:-1])
        shortname = Settings().get_string("degobfuscate.prefix") + shortname
        if shortname in bv.symbols.keys() and func.start != bv.symbols[shortname].address:
            shortname = nextname(bv, shortname)
        func.name = shortname

class Deob(BackgroundTaskThread):
    def __init__(self, bv):
        self.total = len(bv.functions)
        BackgroundTaskThread.__init__(self, f"DeGObfuscate: scanning {self.total} total functions...", True)
        self.bv = bv
        self.match = 0
        self.index = 0

    def run(self):
        for func in self.bv.functions:
            if self.cancelled:
                self.progress = f"DeGObfuscate cancelled, aborting"
                return

            self.index += 1
            if validfunc(self.bv, func):
                self.match += 1
                self.progress = f"DeGObfuscate analyzing ({self.index}/{self.total}) : {func.name}"
                try:
                    deobfunc(self.bv, func)
                except Exception as e:
                    log_warn(f"DeGObfuscate: error while emulating {func.name}: {e}")

        self.progress = f"DeGObfuscate emulated {self.match} functions"

def deob(bv):
    d = Deob(bv)
    d.start()

def deobsingle(bv, func):
    try:
        deobfunc(bv, func)
    except Exception as e:
        log_warn(f"DeGObfuscate: error while emulating {func.name}: {e}")

PluginCommand.register_for_function("DeGObfuscate single function", "Tries to just deobfuscate this function as a gobfuscated string", deobsingle)
PluginCommand.register("DeGObfuscate all functions", "Searches all functions for obfuscated xor strings and attempts light IL emulation to recover them.", deob)
