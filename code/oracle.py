import os
import sys
import subprocess

import env


def rewrite_binary_with_oracle(bin):
    """
    Rewritten binary is named as bin.redfat
    """
    oracle_bin = bin + ".redfat"
    redfat_bin = os.path.join(env.redfat_dir, "redfat")
    patch_cmd = [ redfat_bin, "-Xreads=true", "-Xlowfat=false", bin ]
    p = subprocess.Popen(patch_cmd)
    p.communicate()
    if not os.path.isfile(oracle_bin):
        sys.exit("Failed to use RedFat to create oracle binary. Aborting ...")


def exec_bin(cmd_list):
    redfat_lib_path = os.path.join(env.redfat_dir, "install", "libredfat.so")
    redfat_env = { "LD_PRELOAD" : redfat_lib_path }
    modified_env = { **os.environ, **redfat_env }
    p = subprocess.Popen(cmd_list, env=modified_env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return out, err
