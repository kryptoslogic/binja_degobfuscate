#!/usr/bin/env python
# coding: utf-8

# In[57]:


import os.path
import logging
import struct
from termcolor import colored
from io import BytesIO

from binaryninja import * 
log_to_stderr(LogLevel.ErrorLog)
print(core_version())


# In[2]:


# Create DB from scratch
h = "5c9b30d502e2f103f089607ce699520f88154e3d7988a9db801f2a2a4378bf41"

if os.path.exists(f"./testcases/{h}.bndb"):
    print("Loading existing DB")
    fm = binaryninja.FileMetadata()
    db = fm.open_existing_database(f"./testcases/{h}.bndb")

    if db is None:
        raise Exception("Database doesn't exist")

    bv = db.get_view_of_type('PE') or db.get_view_of_type('ELF')
elif os.path.exists(f"./testcases/{h}"):
    print("Creating DB")
    bv = binaryninja.BinaryViewType.get_view_of_file_with_options(f"./testcases/{h}")
else:
    raise Exception("File doesn't exist...")


# In[3]:


morestack_noctxt_sym = bv.get_symbols_by_name("runtime.morestack_noctxt") or bv.get_symbols_by_name("_runtime.morestack_noctxt") or bv.get_symbols_by_name("runtime_morestack_noctxt") or bv.get_symbols_by_name("_runtime_morestack_noctxt")
slicebytetostring_sym = bv.get_symbols_by_name("runtime.slicebytetostring") or bv.get_symbols_by_name("_runtime.slicebytetostring") or bv.get_symbols_by_name("runtime_slicebytetostring") or bv.get_symbols_by_name("_runtime_slicebytetostring")

morestack_noctxt = bv.get_function_at(morestack_noctxt_sym[0].address)
slicebytetostring = bv.get_function_at(slicebytetostring_sym[0].address)

deobfuscate_candidates = set()

print("{} functions".format(len(bv.functions)))

for func in bv.functions:
    func_callees = func.callees
    if (len(func_callees)) == 2:
        if morestack_noctxt in func_callees and slicebytetostring in func_callees:
            print(func.name)
            for ins in func.instructions:
                ins_type = ins[0][0]
                if ins_type.text != "xor":
                    continue
                src = ins[0][2]
                dst  = ins[0][4]
                if src == "eax" and dst == "eax":
                    continue
                
                deobfuscate_candidates.add(func)
                break
            
           


# In[91]:


logger = logging.getLogger("parser")
logger.setLevel(logging.DEBUG)
#logging.getLogger().setLevel(logging.INFO)

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
        print(chr(left ^ right))
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
        #print("{}={}".format(reg_name, hex(src)))
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
        #print("Executing: {}".format(str(inst.operation)))
        for field in LowLevelILInstruction.ILOperations[inst.operation]:
            handler = "handle_{}".format(inst.operation.name)
            has_handler = hasattr(self, handler)
            if has_handler is False:
                print("Implement: {}".format(str(inst.operation)))
                return None
            else:
                res = getattr(self, handler)(inst)
                return res
    
    def execute(self):
        if self.ip >= len(self.instructions):
            return False
        #print(self.ip)
        instr = self.instructions[self.ip]
        self.ip += 1
        self.handle(instr)
        return True
    
    def run(self):
        while True:
            if not emu.execute():
                break
        print("We're done!")
    
    def __init__(self, candidate):
        self.endianness = candidate.arch.endianness
        self.instructions = candidate.llil

for candidate in deobfuscate_candidates:
    emu = EmuMagic(candidate)
    # candidate.name != "fpkkfenfnamejfgjlfoj_accdmbdpffpomfofhdmd_eamfeondkolifgkfpmjm_glob_func7" and
    if candidate.name != "fpkkfenfnamejfgjlfoj_accdmbdpffpomfofhdmd_nebiohfnhlhlklappnlj_Ddfcadiihliaahccbolg_func5":
        continue
    print(candidate.name)
    emu.run()


# In[ ]:




