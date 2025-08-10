from binaryninja import *

#class main(bv):
    # John Tear
    # Script to find possible vulnerable calls
    
def FindIOCTLDispatcher(bv):
    print("IOCTL Dispatcher")
    print("----------------")
    func = None    

    for inst in bv.hlil_instructions:
        if "MajorFunction" in str(inst):
            print(f"{hex(inst.address)}: {str(inst)}")
            func = str(inst.src)
            break

    print(" ")
    print("Possible IOCTL Comparisons")
    print("--------------------------")
    if func is not None:
        for f in bv.functions:
            if f.name == str(func):
                # this instruction breaks the code
                for block in f.hlil.basic_blocks:
                        for inst in block:
                            match inst:
                                case HighLevelILIf():
                                    if "== 0x" in str(inst):
                                        print(f"{hex(inst.address)}: {str(inst)}")
                                case HighLevelILCase():
                                    if "0x" in str(inst):
                                        print(f"{hex(inst.address)}: {str(inst)}")
                break

def FindDriverFunctions(bv):
    print(" ")
    print("Driver Function Calls")
    print("---------------------")
    functions = ["IoCreateSymbolicLink", "IoCreateDevice"]
    index = 0
    
    while index < len(functions):
        for inst in bv.hlil_instructions:
            if functions[index] in  str(inst):
                print(f"{hex(inst.address)}: {functions[index]}")
            match inst:
                case HighLevelILCall():
                    if functions[index] in str(inst.dest):
                        print(f"{hex(inst.address)}: {functions[index]}")
        index += 1
    
def FindKernelFunctions(bv):
    print(" ")
    print("Kernel Function Calls")
    print("---------------------")
    functions = ["ExAllocatePoolWithTag", "MmMapIoSpace", "ProbeForRead", "ProbeForWrite", "RtlCopyMemory", "memcopy"]
    index = 0
    
    while index < len(functions):
        for inst in bv.hlil_instructions:
            if functions[index] in  str(inst):
                print(f"{hex(inst.address)}: {functions[index]}")
            match inst:
                case HighLevelILCall():
                    if functions[index] in str(inst.dest):
                        print(f"{hex(inst.address)}: {functions[index]}")
        index += 1
    
def FindMsrInstructions(bv):
    print(" ")
    print("MSR Instructions")  
    print("----------------")    
    patterns = [b"\x0f\x30", b"\x0f\x32"]
    descriptions = ["__wrmsr", "__rdmsr"]
    index = 0
        
    while index < len(descriptions):
        addr = bv.start
        while addr < bv.end:
            addr = bv.find_next_data(addr, patterns[index])
            if addr is None:
                break
            print(f"{hex(addr)}: {descriptions[index]}")
            addr+= 1
        index += 1
    
def RunAll(bv):
    FindIOCTLDispatcher(bv)
    FindDriverFunctions(bv)
    FindKernelFunctions(bv)
    FindMsrInstructions(bv)

PluginCommand.register('Plackyhacker\\Find IOCTL Dispatcher', 'Find IOCTL Dispatcher', FindIOCTLDispatcher)
PluginCommand.register('Plackyhacker\\Find Driver Functions', 'Find Driver Functions', FindDriverFunctions)
PluginCommand.register('Plackyhacker\\Find Kernel Functions', 'Find Kernel Functions', FindKernelFunctions)
PluginCommand.register('Plackyhacker\\Find Msr Instructions', 'Find Msr Instructions', FindMsrInstructions)
PluginCommand.register('Plackyhacker\\Run All', 'Run All', RunAll)

