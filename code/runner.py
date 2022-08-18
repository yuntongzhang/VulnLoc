"""
Contains things related to running one run with binary and some arguments.
"""

import os
import json
from copy import deepcopy
import numpy as np

import utils
import values
import tracer
import oracle
import logger


def prepare_args(input_no, poc, poc_fmt):
    # prepare the arguments
    arg_num = len(poc_fmt)
    arg_list = []

    # (YN: added to store "all" input files)
    input_filepath = os.path.join(values.AllInputFolder, "input_" +
                                  str(values.AllInputCounter) + "_" + str(input_no))
    content = 0

    for arg_no in range(arg_num):
        curr_poc_type = poc_fmt[arg_no][0]
        if curr_poc_type == 'bfile':  # write the list into binary file
            content = np.asarray(poc[poc_fmt[arg_no][1]: poc_fmt[arg_no]
                                 [1]+poc_fmt[arg_no][2]]).astype(np.int)
            tmp_filepath = os.path.join(values.TmpFolder, f'tmp_{input_no}')
            utils.write_bin(tmp_filepath, content)
            arg_list.append(tmp_filepath)
        elif curr_poc_type == 'int':
            arg_list.append(int(poc[poc_fmt[arg_no][1]]))
        elif curr_poc_type == 'float':
            arg_list.append(float(poc[poc_fmt[arg_no][1]]))
        elif curr_poc_type == 'str':  # concatenate all the chars together
            arg_list.append(''.join(poc[poc_fmt[arg_no][1]: poc_fmt[arg_no][1]+poc_fmt[arg_no][2]]))
        else:
            raise Exception(f"ERROR: Unknown poc_fmt -> {curr_poc_type}")

    # (YN: added to store "all" input files)
    if values.StoreAllInputs:
        logger.I(f"write input: {input_filepath}")
        if arg_num == 1 and poc_fmt[0][0] == 'bfile':
            utils.write_bin(input_filepath, content)
        else:  # == 'text'
            utils.write_txt(input_filepath, json.dumps(arg_list))

    return arg_list


def prepare_cmd(cmd_list, replace_idx, arg_list):
    replaced_cmd = deepcopy(cmd_list)
    arg_num = len(replace_idx)
    for arg_no in range(arg_num):
        replaced_cmd[replace_idx[arg_no]] = str(arg_list[arg_no])
    replaced_cmd = ''.join(replaced_cmd)
    replaced_cmd = replaced_cmd.split(';')
    return replaced_cmd


def just_trace(input_no, raw_args, poc_fmt, trace_cmd, trace_replace_idx, bin_path):
    processed_args = prepare_args(input_no, raw_args, poc_fmt)
    cmd = prepare_cmd(trace_cmd, trace_replace_idx, processed_args)
    trace = tracer.exec_bin(cmd, bin_path)
    trace_hash = tracer.calc_trace_hash(trace)
    return trace, trace_hash


def gen_report(input_no, raw_args, poc_fmt, trace_cmd, trace_replace_idx, crash_cmd,
		crash_replace_idx, crash_info, seed_trace, bin_path):
    processed_args = prepare_args(input_no, raw_args, poc_fmt)
	# (1) trace
    trace_cmd = prepare_cmd(trace_cmd, trace_replace_idx, processed_args)
    trace = tracer.exec_bin(trace_cmd, bin_path)
    trace_diff_id = tracer.trace_cmp(seed_trace, trace)
    trace_hash = tracer.calc_trace_hash(trace)
	# (2) check against oracle
    crash_cmd = prepare_cmd(crash_cmd, crash_replace_idx, processed_args)
    _, err = oracle.exec_bin(crash_cmd, bin_path)
    crash_result = oracle.check_exploit(err, crash_info)
    return (input_no, trace, trace_hash, crash_result, trace_diff_id)
