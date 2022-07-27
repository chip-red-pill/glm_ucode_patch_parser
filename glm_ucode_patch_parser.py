import os
import sys
import struct

import glm_ucode_disasm

g_pcode = b''
g_match_patch_regs = ()
g_patch_match = {}
g_patch_ram = ()
g_patch_ram_seqwords = ()

def parser_rid_end(patch_data, offset):
    return "END", offset

def parser_rid_init(patch_data, offset):
    global g_match_patch_data
    global g_patch_match
    global g_patch_ram
    global g_patch_ram_seqwords

    g_match_patch_regs = ()
    g_patch_match = {}
    g_patch_ram = ()
    g_patch_ram_seqwords = ()
    return "INIT", offset

def parser_rid_patch_ram(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 4)
    patch_ram_addr, entry_count = struct.unpack_from("<HH", patch_data, offset)
    offset += 4
    assert(len(patch_data) - offset >= entry_count * 8)

    global g_patch_ram
    global g_patch_ram_seqwords
    g_patch_ram = [0,] * 0x180
    g_patch_ram_seqwords = [0,] * 0x80

    assert(patch_ram_addr >= 0x7c00 and patch_ram_addr < 0x7e00)
    patch_ram_idx = patch_ram_addr - 0x7c00

    str_res = "PATCH_RAM: U%04x:\n" % patch_ram_addr
    seqw = 0
    for i in range(entry_count):
        seqw_uop, = struct.unpack_from("<Q", patch_data, offset)
        seqw |= ((seqw_uop >> 48) & 0x3ff) << ((i % 3) * 10)

        g_patch_ram[patch_ram_idx] = seqw_uop & 0xffffffffffff
        g_patch_ram_seqwords[patch_ram_idx // 3] = seqw
        patch_ram_idx += 1

        offset += 8

        if i % 3 == 2:
            for uop_idx in range(3):
                uop_patch_ram_addr = 0x7c00 + (patch_ram_idx // 3 - 1) * 4 + uop_idx
                uop = g_patch_ram[(patch_ram_idx // 3 - 1) * 3 + uop_idx]
                str_match_patch_addr = ("U%04x: " % g_patch_match[uop_patch_ram_addr]) if uop_patch_ram_addr in g_patch_match else ""
                str_res += " U%04x: " % uop_patch_ram_addr + str_match_patch_addr + "%012x " % uop + \
                            glm_ucode_disasm.uop_disassemble(uop, uop_patch_ram_addr) + "\n"
                seqword_sentences, exec_flow_stop = glm_ucode_disasm.process_seqword(uop_patch_ram_addr, uop, seqw, False)
                if len(seqword_sentences):
                    for sws_idx, seqword_sentence in enumerate(seqword_sentences):
                        str_prefix = "%20s" % ("%08x" % seqw if sws_idx == 0 else "") + " "
                        str_res += str_prefix + seqword_sentence + "\n"
            
            seqw = 0
            str_res += "\n"
    
    return str_res.rstrip("\n") + "\n", offset

def parser_rid_match_patch(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 2)
    entry_count, = struct.unpack_from("<H", patch_data, offset)
    offset += 2
    assert(len(patch_data) - offset >= entry_count * 8)

    global g_match_patch_regs
    global g_patch_match

    str_res = "MATCH_PATCH:\n"
    for i in range(entry_count):
        two_match_patch, = struct.unpack_from("<Q", patch_data, offset)
        for match_patch in (two_match_patch & 0x7fffffff, two_match_patch >> 0x1f):
            g_match_patch_regs += match_patch,
            match_addr = match_patch & 0xfffe
            patch_addr = (match_patch >> 16) << 1
            g_patch_match[patch_addr] = match_addr
            str_match_patch = ": U%04x -> U%04x" % (match_addr, patch_addr)
            str_res += " 0x%08x" % match_patch + (str_match_patch if match_patch else "") + "\n"
        offset += 8
    return str_res.rstrip("\n"), offset

def parser_rid_rmw_stg_buf(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 2)
    entry_count, = struct.unpack_from("<H", patch_data, offset)
    offset += 2
    assert(len(patch_data) - offset >= entry_count * 0x12)

    str_res = "RMW STAGING BUF:\n"
    for i in range(entry_count):
        iospecial_addr, and_val, or_val = struct.unpack_from("<HQQ", patch_data, offset)
        str_res += " 0x%03x: AND=0x%016x: OR=0x%016x\n" % (iospecial_addr, and_val, or_val)
        offset += 0x12
    return str_res.rstrip("\n"), offset

def parser_rid_rmw_creg(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 2)
    entry_count, = struct.unpack_from("<H", patch_data, offset)
    offset += 2
    assert(len(patch_data) - offset >= entry_count * 0x14)

    str_res = "RMW CREG:\n"
    for i in range(entry_count):
        creg_addr, and_val, or_val = struct.unpack_from("<LQQ", patch_data, offset)
        str_res += " 0x%03x: AND=0x%016x: OR=0x%016x\n" % (creg_addr, and_val, or_val)
        offset += 0x14
    return str_res.rstrip("\n"), offset

def parser_rid_rmw_uram(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 2)
    entry_count, = struct.unpack_from("<H", patch_data, offset)
    offset += 2
    assert(len(patch_data) - offset >= entry_count * 0x14)

    str_res = "RMW URAM:\n"
    for i in range(entry_count):
        uram_addr, and_val, or_val = struct.unpack_from("<LQQ", patch_data, offset)
        str_res += " 0x%03x: AND=0x%016x: OR=0x%016x\n" % (uram_addr, and_val, or_val)
        offset += 0x14
    return str_res.rstrip("\n"), offset

def parser_rid_rmw_creg_sync(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 2)
    entry_count, = struct.unpack_from("<H", patch_data, offset)
    offset += 2
    assert(len(patch_data) - offset >= entry_count * 0x14)

    str_res = "RMW CREG SYNC:\n"
    for i in range(entry_count):
        creg_addr, and_val, or_val = struct.unpack_from("<LQQ", patch_data, offset)
        str_res += " 0x%03x: AND=0x%016x: OR=0x%016x\n" % (creg_addr, and_val, or_val)
        offset += 0x14
    return str_res.rstrip("\n"), offset

def parser_rid_ucall(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 2)
    uaddr, = struct.unpack_from("<H", patch_data, offset)
    str_res = "UCALL: U%04x" % uaddr
    return str_res, offset + 2

def parser_rid_skip_for_pcu_mbox_op_01(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 8)
    mbox_op_res, def_skip_size, = struct.unpack_from("<LL", patch_data, offset)
    offset += 8
    assert(len(patch_data) - offset >= def_skip_size)
    str_res = "SKIP FOR PCU MBOX OP_01: 0x%08x: 0x%08x" % \
              (mbox_op_res, offset + def_skip_size)
    return str_res, offset

def parser_rid_halt_pcu(patch_data, offset):
    return "HALT PCU", offset

def parser_rid_resume_pcu(patch_data, offset):
    return "RESUME PCU", offset

def parser_rid_write_pcu_ldat(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 6)
    sdat, pdat, entry_count, = struct.unpack_from("<HHH", patch_data, offset)
    offset += 6
    assert(len(patch_data) - offset >= entry_count * 8)

    global g_pcode
    paddr = (((sdat >> 2) & 0xf) * 0x1000 + pdat) * 8
    if len(g_pcode) < paddr:
        g_pcode = g_pcode + b'\x00' * (paddr - len(g_pcode))
    
    str_res = "WRITE PCU LDAT: PDAT=0x%04x: SDAT=0x%04x\n"% (pdat, sdat)
    for i in range(entry_count):
        outval, = struct.unpack_from("<Q", patch_data, offset)
        str_res += " 0x%016x\n" % outval
        g_pcode = g_pcode + struct.pack("<Q", outval)
        offset += 8
    return str_res.rstrip("\n"), offset

def parser_rid_rmw_pcu_mbox_op_05(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 2)
    entry_count, = struct.unpack_from("<H", patch_data, offset)
    offset += 2
    assert(len(patch_data) - offset >= entry_count * 0x0a)

    str_res = "RMW PCU MBOX OP_05:\n"
    for i in range(entry_count):
        op_data, and_val, or_val = struct.unpack_from("<HLL", patch_data, offset)
        str_res += " 0x%04x: AND=0x%08x: OR=0x%08x\n" % (op_data, and_val, or_val)
        offset += 0x0a
    return str_res.rstrip("\n"), offset

def parser_rid_pcu_mbox(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 5)
    opcode, data = struct.unpack_from("<BL", patch_data, offset)
    offset += 5
    str_res = "PCU MBOX: OP=0x%02x, DATA=0x%08x" % (opcode, data)
    return str_res, offset

def parser_rid_skip_for_mode_c000(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 4)
    skip_size, = struct.unpack_from("<L", patch_data, offset)
    offset += 4
    assert(len(patch_data) - offset >= skip_size)
    str_res = "SKIP FOR MODE 0xc000: 0x%08x" % (offset + skip_size)
    return str_res, offset

def parser_rid_skip_for_mode_4000(patch_data, offset):
    str_res = ""
    assert(len(patch_data) - offset >= 4)
    skip_size, = struct.unpack_from("<L", patch_data, offset)
    offset += 4
    assert(len(patch_data) - offset >= skip_size)
    str_res = "SKIP FOR MODE 0x4000: 0x%08x" % (offset + skip_size)
    return str_res, offset

g_parsers = {0x00: parser_rid_end,
             0x01: parser_rid_init,
             0x02: parser_rid_patch_ram,
             0x03: parser_rid_match_patch,
             0x05: parser_rid_rmw_stg_buf,
             0x06: parser_rid_rmw_creg,
             0x07: parser_rid_rmw_uram,
             0x08: parser_rid_rmw_creg_sync,
             0x0a: parser_rid_ucall,
             0x0c: parser_rid_skip_for_pcu_mbox_op_01,
             0x0d: parser_rid_halt_pcu,
             0x0e: parser_rid_resume_pcu,
             0x0f: parser_rid_write_pcu_ldat,
             0x10: parser_rid_rmw_pcu_mbox_op_05,
             0x11: parser_rid_pcu_mbox,
             0x1d: parser_rid_skip_for_mode_c000,
             0x1e: parser_rid_skip_for_mode_4000}

def parse_ucode_patch(patch_data):
    str_res = ""
    offset = 0
    while (offset < len(patch_data)):
        run_id, = struct.unpack_from("<B", patch_data, offset)
        #assert(run_id in g_parsers)
        if run_id not in g_parsers:
            break
        parse_res = g_parsers[run_id](patch_data, offset + 1)
        str_res += "0x%04x: 0x%02x(U%04x): %s\n" % (offset, run_id, (run_id << 2) + 0x226c, parse_res[0])
        offset = parse_res[1] 
    return str_res

def save_ms_array(array_idx, ms_array_data, file_path):
    fo = open(file_path, "w")
    fo.write("array %02x:" % array_idx)
    for addr, data_item in enumerate(ms_array_data):
        if addr % 4 == 0:
            fo.write("\n%04x: " % addr)
        fo.write(" %012x" % data_item)
    for i in range((addr + 1) % 4):
        fo.write(" %012x" % 0)
    fo.write("\n")
    fo.close()

def main():
    if len(sys.argv) < 2:
        print("Usage: glm_ucode_patch_parser <decoded_patch_path> [-v]")
        return -1
    
    patch_path = sys.argv[1]
    fi = open(patch_path, "rb")
    patch_data = fi.read()
    fi.close()

    out_file_path = os.path.splitext(patch_path)[0] + ".txt"
    parsed_data = parse_ucode_patch(patch_data)
    fo = open(out_file_path, "w")
    fo.write(parsed_data)
    fo.close()

    verbose = len(sys.argv) > 2 and sys.argv[2] == "-v"
    if verbose: 
        pcode_out_file_path = os.path.splitext(patch_path)[0] + ".pcode.bin"
        fo = open(pcode_out_file_path, "wb")
        fo.write(g_pcode)
        fo.close()

        global g_match_patch_regs
        if len(g_match_patch_regs):
            g_match_patch_regs += (0,) * (0x40 - len(g_match_patch_regs))
            save_ms_array(3, g_match_patch_regs, os.path.splitext(patch_path)[0] + ".ms_array3.txt")
    
        if len(g_patch_ram):
            assert(len(g_patch_ram_seqwords))
            save_ms_array(2, g_patch_ram_seqwords, os.path.splitext(patch_path)[0] + ".ms_array2.txt")

            patch_ram_array_data = [0,] * 0x200
            for idx, patch_ram_item in enumerate(g_patch_ram):
                patch_ram_array_data[(idx // 3) + (idx % 3) * 0x80] = patch_ram_item
            save_ms_array(4, patch_ram_array_data, os.path.splitext(patch_path)[0] + ".ms_array4.txt")
    
    print("File [%s] processed" % patch_path)
    return 0

main()
