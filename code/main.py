import argparse
import configparser
import string
import os
import numpy as np

import values
import utils

import fuzz
import patchloc


def parse_args():
    parser = argparse.ArgumentParser(description="ConcFuzz")
    parser.add_argument('--config', type=str, required=True,
                        help="The path of config file")
    parser.add_argument('--tag', type=str, required=True,
                        help="The corresponding CVE id")
    parser.add_argument('--timeout', type=int, default=30,
                        help='Time allocated for fuzzing (in mins).')
    parser.add_argument('--verbose', default=True, action='store_true',
                        help="Whether print out the debugging info")
    parser.add_argument('--process-num', dest='process_num', type=int, default=10,
                        help="The number of processes to use.")
    # localization only
    parser.add_argument('--func', default='calc', choices=['calc', 'show'],
                        help='The function for execution during patchloc (calc/show).')
    parser.add_argument('--show-num', dest='show_num', type=int, default=10,
                        help="The number of instructions to show")
    args = parser.parse_args()

    # check the validity of args
    config = configparser.ConfigParser()
    config.read(args.config)
    if args.tag not in config.sections():
        raise Exception(f"ERROR: Please provide the configuration file for {args.tag}")

    # process cmd line arguments
    values.GlobalTimeout = args.timeout * 60
    values.LocalTimeout = args.timeout * 60
    values.Tag = args.tag
    values.Verbose = args.verbose
    values.ProcessNum = args.process_num
    values.ShowNum = args.show_num
    values.PatchLocFunc = args.func

    # read & processing config file
    detailed_config = {}
    for key, value in config.items(args.tag):
        if key == 'folder':
            if not os.path.exists(value):
                raise Exception(f"ERROR: The folder does not exist -> {value}")
            detailed_config[key] = value
        elif key == 'bin_path':
            if not os.path.exists(value):
                raise Exception(f"ERROR: The binary does not exist -> {value}")
            detailed_config[key] = value
        else:
            detailed_config[key] = value.split(';')

    # check whether it contains all the required attributes
    if len(set(detailed_config.keys()) & set(values.DefaultItems)) != len(values.DefaultItems):
        raise Exception(
            f"ERROR: Missing required attributes in config.ini "
			f"-> Required attributes: {values.DefaultItems}")

    # check poc & poc_fmt & mutate_range
    arg_num = len(detailed_config['poc'])
    if (arg_num != len(detailed_config['poc_fmt'])
		and arg_num != len(detailed_config['mutate_range'])):
        raise Exception("ERROR: Your defined poc is not matched with poc_fmt/mutate_range")

    # (YN: determine how to write inputs)
    if arg_num == 1 and detailed_config['poc_fmt'][0] == 'bfile':
        detailed_config['input_format'] = 'bfile'
    else:
        detailed_config['input_format'] = 'text'

    processed_arg = []
    # each element is in the fmt of [<type>, <start_idx>, <size>, <mutate_range>]
    processed_fmt = []
    for arg_no in range(arg_num):
        curr_poc_fmt = detailed_config['poc_fmt'][arg_no]
        curr_poc = detailed_config['poc'][arg_no]
        if curr_poc_fmt == 'bfile':
            if not os.path.exists(curr_poc):
                raise Exception(f"ERROR: Exploit file does not exist -> {curr_poc}")
            content = utils.read_bin(curr_poc)
            processed_fmt.append(['bfile', len(processed_arg), len(content), range(256)])
            processed_arg += content
        elif curr_poc_fmt == 'int':
            try:
                tmp = detailed_config['mutate_range'][arg_no].split('~')
                mutate_range = range(int(tmp[0]), int(tmp[1]))
            except Exception as e:
                raise Exception(
                    'ERROR: Please check the value of mutate_range in your config file.') from e
            processed_fmt.append(['int', len(processed_arg), 1, mutate_range])
            processed_arg.append(int(curr_poc))
        elif curr_poc_fmt == 'float':
            try:
                tmp = detailed_config['mutate_range'][arg_no].split('~')
                mutate_range = list(np.arange(float(tmp[0]), float(tmp[1]), float(tmp[2])))
            except Exception as e:
                raise Exception(
                    'ERROR: Please check the value of mutate_range in your config file.') from e
            processed_fmt.append(['float', len(processed_arg), 1, mutate_range])
            processed_arg.append(float(curr_poc))
        elif curr_poc_fmt == 'str':
            processed_fmt.append(['str', len(processed_arg), len(curr_poc), list(string.printable)])
            processed_arg += list(curr_poc)
        else:
            raise Exception(f"ERROR: Unknown type of arguments -> {curr_poc_fmt}")

    detailed_config['poc'] = processed_arg
    detailed_config['poc_fmt'] = processed_fmt
    detailed_config.pop('mutate_range')

    # process the optional args
    if 'global_timeout' not in detailed_config:  # overall global timeout
        detailed_config['global_timeout'] = values.GlobalTimeout
    else:
        detailed_config['global_timeout'] = int(detailed_config['global_timeout'][0])
    if 'local_timeout' not in detailed_config:  # local timeout for each seed
        detailed_config['local_timeout'] = values.LocalTimeout
    else:
        detailed_config['local_timeout'] = int(detailed_config['local_timeout'][0])
    if 'rand_seed' not in detailed_config:  # the randomization seed
        detailed_config['rand_seed'] = values.DefaultRandSeed
    else:
        detailed_config['rand_seed'] = int(detailed_config['rand_seed'][0])
    if 'mutation_num' not in detailed_config:  # the number of mutations for each byte
        detailed_config['#mutation'] = values.DefaultMutateNum
    else:
        detailed_config['#mutation'] = int(detailed_config['mutation_num'][0])
        detailed_config.pop('mutation_num')
    if 'combination_num' not in detailed_config:
        detailed_config['#combination'] = values.DefaultMaxCombination
    else:
        detailed_config['#combination'] = int(detailed_config['combination_num'][0])
        detailed_config.pop('combination_num')
    if 'max_combine_num' in detailed_config:
        values.MaxCombineNum = int(detailed_config['max_combine_num'][0])
    if 'tmp_filename_len' in detailed_config:  # the length of tmp filename
        utils.FileNameLen = int(detailed_config['tmp_filename_len'][0])
    # (YN: added optional storage of all generated inputs files)
    if 'store_all_inputs' not in detailed_config:  # whether to store all generated inputs
        detailed_config['store_all_inputs'] = False
    else:
        detailed_config['store_all_inputs'] = detailed_config['store_all_inputs'][0] == 'True'

    # get all the replace idx in the cmd
    tmp = ';'.join(detailed_config['trace_cmd']).split('***')
    detailed_config['trace_cmd'] = []
    detailed_config['trace_replace_idx'] = []
    for idx, token in enumerate(tmp):
        detailed_config['trace_cmd'].append(token)
        detailed_config['trace_cmd'].append('')
        detailed_config['trace_replace_idx'].append(2 * idx + 1)
    detailed_config['trace_cmd'] = detailed_config['trace_cmd'][:-1]
    detailed_config['trace_replace_idx'] = detailed_config['trace_replace_idx'][:-1]

    tmp = ';'.join(detailed_config['crash_cmd']).split('***')
    detailed_config['crash_cmd'] = []
    detailed_config['crash_replace_idx'] = []
    for idx, token in enumerate(tmp):
        detailed_config['crash_cmd'].append(token)
        detailed_config['crash_cmd'].append('')
        detailed_config['crash_replace_idx'].append(2 * idx + 1)
    detailed_config['crash_cmd'] = detailed_config['crash_cmd'][:-1]
    detailed_config['crash_replace_idx'] = detailed_config['crash_replace_idx'][:-1]

    return detailed_config


if __name__ == '__main__':
    parsed_config = parse_args()
    fuzz.run(parsed_config)
    patchloc.run(parsed_config)
