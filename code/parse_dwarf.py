import subprocess
import operator
import string
import logging
import os

from elftools.elf.elffile import ELFFile

import utils


def find_end_curly_bracket(file_path, start_line, end_line):
    content = utils.read_txt(file_path)
    current_line = end_line - 1
    start_line = start_line - 1
    tag = False
    while current_line >= start_line:
        if len(content[current_line]) > 0 and content[current_line][0] == '}':
            tag = True
            break
        current_line = current_line - 1
    if tag:
        return current_line + 1
    raise Exception(f"ERROR: Cannot find the last curly bracket within [{start_line}, {end_line}]")

# A function to do the readelf part which gives me linenumer :: address for each file


def readELF(filepath, flineNumberDict, mainLine, srcfilepath):
    filename = srcfilepath.split('/')[-1]

    p1 = subprocess.Popen(['readelf', '-wL', filepath],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = p1.communicate()
    outlist = out.split('File name')
    mainAddrList = []
    # Lists that maintain the file starting and ending boundaries
    fileBoundRangesDict = {}
    fileBoundRangesList = []
    fileBoundIndexList = []
    found = False

    # Get all the filenames
    for out in outlist:
        out = 'File name' + out
        paragraphs = out.split('\n\n')

        first = -1

        for paragraph in paragraphs:
            paragraph += '\n'

            lines = paragraph.split('\n')
            for line in lines:
                a = line.rstrip('\n').split(None)
                # print(a)
                if len(a) < 3:
                    continue
                if a[2][0:2] == '0x':
                    # print(a[0])
                    if not a[0] in fileBoundRangesDict:
                        # if not firstFound:
                        first = a[2]
                        pfilename = a[0]
                        fileBoundRangesDict[pfilename] = int(first, 16)

                    if not a[0] in flineNumberDict:
                        flineNumberDict[a[0]] = {}

                    flineNumberDict[a[0]][a[2]] = a[1]

                    # Assuming that the main function is present in the file correspnding
                    # to source executable
                    if a[1] == str(mainLine) and (a[0] == filename):
                        mainAddrList.append(a[2])
                        found = True

    sorted_fileBoundRangesDict = sorted(fileBoundRangesDict.items(), key=operator.itemgetter(1))

    fileBoundRangesList = [x[1] for x in sorted_fileBoundRangesDict]
    fileBoundIndexList = [x[0] for x in sorted_fileBoundRangesDict]

    if found:
        return mainAddrList[0], fileBoundRangesList, fileBoundIndexList
    return None, fileBoundRangesList, fileBoundIndexList


def get_var_size(die_dict, type_die_idx):
    type_die = die_dict[type_die_idx]
    if type_die.tag == 'DW_TAG_base_type':
        type_size = type_die.attributes['DW_AT_byte_size'].value
        return ['basic', type_size]
    elif type_die.tag == 'DW_TAG_array_type':
        new_type_die_idx = type_die.cu.cu_offset + type_die.attributes['DW_AT_type'].value
        tmp = get_var_size(die_dict, new_type_die_idx)
        element_num = -1
        for sub_die in type_die.iter_children():
            if sub_die.tag == 'DW_TAG_subrange_type' and 'DW_AT_upper_bound' in sub_die.attributes:
                element_num = sub_die.attributes['DW_AT_upper_bound'].value
        if element_num < 0:
            raise Exception(f"ERROR: Cannot find the #elements in the array!\n{type_die.__str__()}")
        return ['array', tmp[1]*element_num]
    elif type_die.tag == 'DW_TAG_pointer_type':
        new_type_die_idx = type_die.cu.cu_offset + type_die.attributes['DW_AT_type'].value
        tmp = get_var_size(die_dict, new_type_die_idx)
        if tmp[0][0] == '*':
            return ['*'+tmp[0], tmp[1]]
        else:
            return ['*', tmp[1]]
    elif type_die.tag == 'DW_TAG_structure_type':
        if ('DW_AT_declaration' in type_die.attributes
                and type_die.attributes['DW_AT_declaration'].value):
            return ['struct', -1]
        else:
            return ['struct', type_die.attributes['DW_AT_byte_size'].value]
    elif type_die.tag in ['DW_TAG_typedef', 'DW_TAG_const_type']:
        new_type_die_idx = type_die.cu.cu_offset + type_die.attributes['DW_AT_type'].value
        return get_var_size(die_dict, new_type_die_idx)
    else:
        raise Exception(f"ERROR: Unknown type! -> {type_die}")


class DwarfParser():
    def __init__(self, bin_path):
        with open(bin_path, 'rb') as f:
            elffile = ELFFile(f)
            self.dwarfinfo = elffile.get_dwarf_info()
        logging.debug(f"Read dwarf info from file -> {bin_path}")
        self.bin_path = bin_path

    def bin2func(self, target_addr):
        target_cu = None
        for CU in self.dwarfinfo.iter_CUs():
            top_die = CU.get_top_DIE()
            try:
                cu_min_addr = top_die.attributes['DW_AT_low_pc'].value
                cu_max_addr = cu_min_addr + top_die.attributes['DW_AT_high_pc'].value
            except:
                logging.debug(f"Warning: Cannot find the DW_AT_low_pc & DW_AT_high_pc attributes!"
                    f"\n{top_die.__str__()}")
            else:
                if target_addr >= cu_min_addr and target_addr < cu_max_addr:
                    target_cu = CU
                    break
        if target_cu is None:
            raise Exception(f"ERROR: Cannot find the CU containing target addr -> {target_addr}")

        target_die = None
        next_die = None
        for die in target_cu.iter_DIEs():
            if die.tag == 'DW_TAG_subprogram':
                try:
                    die_min_addr = die.attributes['DW_AT_low_pc'].value
                    die_max_addr = die_min_addr + die.attributes['DW_AT_high_pc'].value
                except:
                    logging.debug(f"Warning: Cannot find the DW_AT_low_pc & "
                        f"DW_AT_high_pc attributes!\n{die.__str__()}")
                else:
                    if target_die is not None:
                        next_die = die
                        break
                    if target_addr >= die_min_addr and target_addr < die_max_addr:
                        target_die = die
        if target_die is None:
            raise Exception(
                f"ERROR: Cannot find the function containing the target addr -> {target_addr}")
        file_dir = target_die.cu.get_top_DIE().attributes['DW_AT_comp_dir'].value
        file_name = target_die.cu.get_top_DIE().attributes['DW_AT_name'].value
        file_path = os.path.join(file_dir, file_name)
        func_name = target_die.attributes['DW_AT_name'].value
        func_decl_line = target_die.attributes['DW_AT_decl_line'].value
        logging.info(f"The address <{target_addr}> can be found below:\nfile: {file_path}\n"
            f"func name: {func_name}\nfunc decl line: {func_decl_line}")
        if next_die is None:
            raise Exception(f"ERROR: Cannot find the next function after function <{func_name}>")
        next_func_decl_line = next_die.attributes['DW_AT_decl_line'].value
        logging.info(f'The starting line of function after <{func_name}>: {next_func_decl_line}')
        last_curly_bracket_line = find_end_curly_bracket(
            file_path, func_decl_line, next_func_decl_line)
        logging.info(f'The ending line of function <{func_name}>: {last_curly_bracket_line}')

        return file_path, func_name, func_decl_line, last_curly_bracket_line, target_die

    def get_func_src_bound(self):
        func_src_bounds = {}
        for CU in self.dwarfinfo.iter_CUs():
            top_die = CU.get_top_DIE()
            filepath = os.path.join(
                top_die.attributes['DW_AT_comp_dir'].value, top_die.attributes['DW_AT_name'].value)
            func_src_bounds[filepath] = {}
            for DIE in CU.iter_DIEs():
                if DIE.tag == "DW_TAG_subprogram":
                    if ("DW_AT_name" not in DIE.attributes
                            or "DW_AT_decl_line" not in DIE.attributes):
                        continue
                    func_name = DIE.attributes["DW_AT_name"].value
                    src_line = DIE.attributes["DW_AT_decl_line"].value
                    func_src_bounds[filepath][func_name] = src_line
        return func_src_bounds

    def get_main_addr(self):
        func_bounds = self.get_func_src_bound()
        main_tag = 0
        src_filepath = ''
        main_line = -1
        for filepath, name_to_line in func_bounds.items():
            for func_name, line in name_to_line.items():
                if func_name == 'main':
                    main_tag += 1
                    src_filepath = filepath
                    main_line = line
        if main_tag != 1:
            raise Exception(f"ERROR: There are {main_tag} main functions.")
        logging.info(f"Here is the main function in the source -> {src_filepath}: {main_line}")

        flineNumberDict = {}
        main_addr, fileBoundRangesList, fileBoundIndexList = readELF(
            self.bin_path, flineNumberDict, main_line, src_filepath)
        logging.info(f"Here is the main address in binary -> {main_addr}")
        return flineNumberDict, fileBoundRangesList, fileBoundIndexList, src_filepath

    def get_all_dies(self):
        die_dict = {}
        for CU in self.dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                die_dict[DIE.offset] = DIE
        return die_dict

    def get_live_vars(self, func_die, die_dict):
        # get global variables
        global_dies = []
        CU = func_die.cu
        for die in CU.iter_DIEs():
            if die.tag == 'DW_TAG_variable' and die.get_parent().tag == 'DW_TAG_compile_unit':
                if ('DW_AT_location' in die.attributes
                        and len(die.attributes['DW_AT_location'].value) > 0
                        and die.attributes['DW_AT_location'].value[0] == 3):
                    global_dies.append(die)
        # get all local variables
        die_info = {'var_dies': [], 'arg_dies': [], 'block_dies': []}
        for child_die in func_die.iter_children():
            if child_die.tag == 'DW_TAG_variable':
                die_info['var_dies'].append(child_die)
            elif child_die.tag == 'DW_TAG_formal_parameter':
                die_info['arg_dies'].append(child_die)
            elif child_die.tag == 'DW_TAG_lexical_block':
                die_info['block_dies'].append(child_die)
            else:
                pass
        block_var_dies = {}
        for die in die_info['block_dies']:
            block_var_dies[die.offset] = []
            for child_die in die.iter_children():
                if child_die.tag == 'DW_TAG_variable':
                    block_var_dies[die.offset].append(child_die)
        # get the type of all the variables
        live_vars_info = {
            'lvars': [],
            'args': [],
            'gvars': []
        }
        for die in die_info['var_dies']:
            live_vars_info['lvars'].append(
                self.parse_var(die_dict, die)
            )
        for die in die_info['arg_dies']:
            live_vars_info['args'].append(
                self.parse_var(die_dict, die)
            )
        for _, dies in block_var_dies.items():
            for die in dies:
                live_vars_info['lvars'].append(self.parse_var(die_dict, die))
        for die in global_dies:
            live_vars_info['gvars'].append(self.parse_var(die_dict, die))
        return live_vars_info

    def parse_var(self, die_dict, die):
        var_name = die.attributes['DW_AT_name'].value
        decl_line = die.attributes['DW_AT_decl_line'].value
        type_die_idx = die.cu.cu_offset + die.attributes['DW_AT_type'].value
        tmp = get_var_size(die_dict, type_die_idx)
        var_type = tmp[0]
        var_size = tmp[1]
        return var_name, decl_line, var_type, var_size

    # def extract_func_live_vars(self):


def get_source_line(bin_path, target_addr_str):
    target_value = int(target_addr_str, 16)
    end_value = target_value + 1
    end_str = hex(end_value)
    cmd_list = ['objdump', '-S', '-l', f"--start-address={target_addr_str}",
        f"--stop-address={end_str}", bin_path]
    p1 = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = p1.communicate()
    content = out.split('\n')
    # process target_addr_str
    tag = None
    for idx, value in enumerate(target_addr_str):
        if value not in ['0', 'x']:
            tag = target_addr_str[idx:]
            break
    line_num = len(content)
    for line_no in range(line_num):
        if tag in content[line_no]:
            if (line_no+2) < line_num:
                return content[line_no+2]
    return None


def get_bin_line(bin_path, target_src_str):
    cmd_list = ['objdump', '-S', '-l', bin_path]
    p1 = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = p1.communicate()
    content = out.split('\n')
    # process target_src_str
    src_file = '-'.join(target_src_str.split('-')[:-1])
    src_line_num = target_src_str.split('-')[-1]
    tag = src_file + ':' + src_line_num
    line_num = len(content)
    start_line_no_list = []
    for line_no in range(line_num):
        if tag in content[line_no]:
            start_line_no_list.append(line_no)
    if len(start_line_no_list) == 0:
        raise Exception(f"Cannot find the target src line -> {target_src_str}")
    addr_collection = []
    for start_line_no in start_line_no_list:
        tag = False
        addr_list = []
        for line_no in range(start_line_no, line_num):
            line = content[line_no].split()
            if len(line) == 0:
                if tag:
                    break
                else:
                    continue
            if line[0][-1] == ':':
                tmp = line[0][:-1]
                addr_tag = True
                for tmp2 in tmp:
                    if tmp2 not in string.hexdigits:
                        addr_tag = False
                        break
                if addr_tag and tag is False:
                    tag = True
                    addr_list.append('0x' + '0'*(16-len(tmp)) + tmp)
                elif addr_tag and tag:
                    addr_list.append('0x' + '0'*(16-len(tmp)) + tmp)
                elif addr_tag is False and tag:
                    break
                else:
                    continue
            else:
                if tag:
                    break
        addr_collection += addr_list
    return addr_collection
