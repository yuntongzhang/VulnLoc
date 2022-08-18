import subprocess
import os
import sys
import hashlib

import values


def rewrite_trace_binary(bin_path):
    """
    Rewritten binary is named as bin.trace
    """
    trace_bin_path = bin_path + ".trace"
    curr_dir = os.getcwd()
    os.chdir(values.e9patch_dir)
    patch_cmd = ['./e9tool', '-M', 'condjump', '-P', 'entry((static)addr)@printaddr',
                 '-o', trace_bin_path, bin_path]
    p = subprocess.Popen(patch_cmd)
    p.communicate()
    if not os.path.isfile(trace_bin_path):
        sys.exit("Failed to use e9patch to create trace binary. Aborting ...")
    os.chdir(curr_dir)


def exec_bin(cmd_list, bin_path):
    trace_bin_path = bin_path + ".trace"
    cmd_list = [trace_bin_path if s == bin_path else s for s in cmd_list]
    p = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         encoding='utf-8', errors='replace')
    _, err = p.communicate()
    # parse output (stderr)
    if_list = []
    for line in err.split("\n"):
        if line.startswith("0x"):
            if_list.append(line)
    return if_list


def calc_trace_hash(trace):
    trace_str = '\n'.join(trace)
    return hashlib.sha256(trace_str.encode('utf-8')).hexdigest()


def trace_cmp(seed_trace, trace):
    min_len = min(len(seed_trace), len(trace))
    for idx in range(min_len):
        if seed_trace[idx] != trace[idx]:
            return idx
    return min_len


def dynamorio_exec_bin(cmd_list):
    # craft tracing command
    tracer_cmd_list = [values.dynamorio_path, '-c', values.iftracer_path, '--']
    tracer_cmd_list.extend(cmd_list)
    # execute command
    p1 = subprocess.Popen(tracer_cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          encoding='utf-8', errors='replace')
    out, _ = p1.communicate()
    # parse the output
    if_list = []
    for aline in out.split("\n"):
        if '0x00000000004' in aline:
            t = aline.split(' => ')
            if_list.append(t[0])
    return if_list
