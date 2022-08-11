import os
import sys
import subprocess

import values


def rewrite_binary_with_oracle(bin_path):
    """
    Rewritten binary is named as bin.redfat
    """
    oracle_bin_path = bin_path + ".redfat"
    redfat_bin = os.path.join(values.redfat_dir, "redfat")
    patch_cmd = [redfat_bin, "-Xreads=true", "-Xlowfat=false", "-o", oracle_bin_path, bin_path]
    p = subprocess.Popen(patch_cmd)
    p.communicate()
    if not os.path.isfile(oracle_bin_path):
        sys.exit("Failed to use RedFat to create oracle binary. Aborting ...")


def exec_bin(cmd_list, bin_path):
    """
    cmd_list is the original cmd.
    """
    oracle_bin_path = bin_path + ".redfat"
    cmd_list = [oracle_bin_path if s == bin_path else s for s in cmd_list]
    redfat_lib_path = os.path.join(values.redfat_dir, "install", "libredfat.so")
    redfat_env = {"LD_PRELOAD": redfat_lib_path}
    modified_env = {**os.environ, **redfat_env}
    p = subprocess.Popen(cmd_list, env=modified_env, encoding='utf-8', errors='replace',
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return out, err


def check_exploit(err, crash_info):
    """
    Check stderr to decide whether the oracle indicates pass/fail on the execution.
    """
    tmp = err.split('\n')
    oracle_type = crash_info[0]
    if oracle_type == 'valgrind':
        line_num = len(tmp)
        for line_no in range(line_num):
            item = tmp[line_no]
            tmp2 = item.split()
            if (len(tmp2) >= 2
                    and len(tmp2[0]) >= 2
                    and tmp2[0][:2] == '=='
                    and tmp2[1] == 'Invalid'):
                target_line_no = line_no + 3
                if target_line_no < line_num:
                    if crash_info[2] in tmp[target_line_no]:
                        return 'm'
        return 'b'
    elif oracle_type == 'asan':
        tag = '#' + crash_info[1]
        for item in tmp:
            tmp2 = item.split()
            if len(tmp2) == 0:
                break
            if item.split()[0] == tag:
                if crash_info[2] in item:
                    return 'm'
        return 'b'
    elif oracle_type == "assert":
        if crash_info[1] in err:
            return "m"
        else:
            return "b"
    elif oracle_type == "redfat":
        if "REDFAT ERROR" in err:
            return "m"
        else:
            return "b"
    else:
        raise Exception(f'ERROR: Unknown crash info -> {crash_info}')
