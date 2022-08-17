import argparse
import configparser
import logging
import os
import string
import shutil
import json
from time import time
from multiprocessing import Pool
import numpy as np

import utils
import runner
import tracer
import oracle
import values
from logger import init_log
from sensitivity_map import SensMap


def parse_args():
    parser = argparse.ArgumentParser(description="ConcFuzz")
    parser.add_argument('--config_file', dest='config_file', type=str, required=True,
                        help="The path of config file")
    parser.add_argument('--tag', dest='tag', type=str, required=True,
                        help="The corresponding CVE id")
    parser.add_argument('--verbose', dest='verbose', type=str, default='True',
                        help="Whether print out the debugging info")
    args = parser.parse_args()

    # check the validity of args
    config = configparser.ConfigParser()
    config.read(args.config_file)
    if args.tag not in config.sections():
        raise Exception(f"ERROR: Please provide the configuration file for {args.tag}")

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

    return args.tag, detailed_config, args.verbose


def choose_seed():
    """
    :returns: None if no seed is selected.
    """
    # get all the seeds which have not been selected
    seed_num = len(values.SeedPool)
    ns_idx = []
    for seed_no in range(seed_num):
        if values.SeedPool[seed_no][0] is False:
            ns_idx.append(seed_no)
    if len(ns_idx) == 0:
        return None
    else:
        selected_id = np.random.choice(ns_idx)
        values.SeedPool[selected_id][0] = True
        return values.SeedTraceHashList[selected_id], values.SeedPool[selected_id][1]


def mutate_inputs(seed, poc_fmt, mutation_num, mutate_idx):
    redundant_mutations = mutation_num * 2
    inputs = np.tile(seed, (redundant_mutations, 1))
    # get the mutate range for the specific mutate_idx
    for idx in mutate_idx:
        mutate_range = None
        for arg_fmt in poc_fmt:
            if idx >= arg_fmt[1] and idx < (arg_fmt[1] + arg_fmt[2]):
                mutate_range = arg_fmt[3]
        if mutate_range is None:
            raise Exception(f"ERROR: Cannot find the corresponding fmt -> mutate_idx: {idx}")
        mutate_values = np.random.choice(mutate_range, redundant_mutations)
        inputs[:, idx] = mutate_values
    inputs = np.unique(inputs, axis=0)[: mutation_num]
    return inputs


# (YN: added function to store generated inputs)
def store_input(output_folder, input_counter, config_info, content):
    input_filepath = os.path.join(output_folder, "input_" + str(input_counter))
    logging.info(f"write input: {input_filepath}")
    if config_info['input_format'] == 'bfile':
        utils.write_bin(input_filepath, content)
    else:  # == 'text'
        utils.write_txt(input_filepath, json.dumps(list(content)))
    input_counter += 1
    return input_counter


def process_poc(config_info):
    # generate the trace for the poc
    trace, trace_hash = runner.just_trace(0, config_info['poc'], config_info['poc_fmt'],
            config_info['trace_cmd'], config_info['trace_replace_idx'], config_info['bin_path'])
    logging.debug(f'PoC Hash: {trace_hash}')
    seed_len = len(config_info['poc'])
    # save the trace
    values.TraceHashCollection.append(trace_hash)
    path = os.path.join(values.TraceFolder, trace_hash)
    # utils.write_pkl(path, trace)
    np.savez(path, trace=trace)
    # add the report
    values.ReportCollection.append([trace_hash, 'm'])
    # add into seed pool
    values.SeedPool.append([False, config_info['poc']])
    values.SeedTraceHashList.append(trace_hash)
    logging.info('Finish processing the poc!')
    return trace, seed_len


def real_concfuzz_loop(config_info, poc_trace, seed_len):
    stime = time()  # starting time
    round_no = 0
    while True:
        round_no += 1
        # choose seed & load seed_trace
        selection_result = choose_seed()
        if selection_result is None:
            logging.debug(f"[R-{round_no}] Finish processing all the seeds!")
            break
        selected_seed_trace_hash, selected_seed = selection_result
        logging.debug(f"[R-{round_no}] Select seed -> {selected_seed_trace_hash}")
        seed_pool_str = '\n'.join([f'{values.SeedTraceHashList[id]}: {values.SeedPool[id][0]}'
                                   for id in range(len(values.SeedPool))])
        logging.debug(f"The status of current seed pool:\n{seed_pool_str}")

        trace_path = os.path.join(values.TraceFolder, selected_seed_trace_hash + '.npz')
        if round_no == 1:
            selected_seed_trace = poc_trace
        else:
            selected_seed_trace = np.load(trace_path)
            # selected_seed_trace = utils.read_pkl(trace_path)
        logging.info(f'len(Seed Trace): {len(selected_seed_trace)}')

        # initialize sensitivity map
        sens_map = SensMap(seed_len, len(selected_seed_trace), config_info['#combination'])

        # check each selected seed
        subround_no = 0
        while True:
            subround_no += 1
            # select mutate byte
            mutate_idx = sens_map.select_mutate_idx()
            if mutate_idx is None:  # exit if all the bytes get mutated
                break
            actual_mutate_loc = sens_map.retrieve_mutate_idx(mutate_idx)
            logging.debug(f"[R-{round_no}-{subround_no}] Select the mutate idx ->"
			 	f"{mutate_idx}: {actual_mutate_loc}")
            sens_map.mark_mutate_idx(mutate_idx)
            # mutate inputs
            inputs = mutate_inputs(selected_seed, config_info['poc_fmt'],
								   config_info['#mutation'], actual_mutate_loc)
            logging.debug(f"Shape(mutated_inputs): {inputs.shape}")
            # execute all the mutated inputs
            # each element is in the fmt of [id, trace, trace_hash, crash_result, trace_diff_id]
            result_collection = []
            input_num = len(inputs)
            pool = Pool(utils.ProcessNum)
            for input_no in range(input_num):
                pool.apply_async(
                    runner.gen_report,
                    args=(input_no, inputs[input_no], config_info['poc_fmt'],
						  config_info['trace_cmd'], config_info['trace_replace_idx'],
						  config_info['crash_cmd'], config_info['crash_replace_idx'],
                          config_info['crash_tag'], selected_seed_trace, config_info['bin_path']),
                    callback=result_collection.append
                )
            pool.close()
            pool.join()
            logging.debug(f"#(Missed): {input_num - len(result_collection)}")
            # Delete all the tmp files
            shutil.rmtree(values.TmpFolder)
            os.mkdir(values.TmpFolder)
            values.AllInputCounter += 1
            # if input_num != len(result_collection):
            # 	missed_ids = set(range(input_num)) - set([item[0] for item in result_collection])
            # 	missed_inputs = [inputs[id] for id in missed_ids]
            # 	output_path = os.path.join(OutFolder, 'missed_inputs.pkl')
            # 	utils.write_pkl(output_path, missed_inputs)
            # 	raise Exception("ERROR: #execution does not match with #input."
			# 			"-> Missed inputs can be found in %s" % output_path)

            # collect all the trace
            diff_collection = set()
            crash_collection = {'m'}
            for item in result_collection:
                input_no, trace, trace_hash, crash_result, trace_diff_id = item
                diff_collection.add(trace_diff_id)
                crash_collection.add(crash_result)
                # save the trace
                if trace_hash not in values.TraceHashCollection:
                    values.TraceHashCollection.append(trace_hash)
                    trace_path = os.path.join(values.TraceFolder, trace_hash)
                    # utils.write_pkl(trace_path, item[1])
                    np.savez(trace_path, trace=trace)
                    # (YN: added to store "interesting" (concentrated) input files)
                    values.ConcentratedInputCounter = store_input(
                        values.ConcentratedInputFolder, values.ConcentratedInputCounter,
						config_info, inputs[input_no])
                # check whether to add it into the seed pool
                if crash_result == 'm' and trace_hash not in values.SeedTraceHashList:
                    values.SeedPool.append([False, inputs[input_no]])
                    values.SeedTraceHashList.append(trace_hash)
                # Update reports
                if [trace_hash, crash_result] not in values.ReportCollection:
                    values.ReportCollection.append([trace_hash, crash_result])

            logging.debug(f"#Diff: {len(diff_collection)}; #ExeResult: {len(crash_collection)};"
				f"#seed: {len(values.SeedPool)}")

            # update sensitivity map
            sens_map.update_maps(mutate_idx, diff_collection, crash_collection)
            # check whether it timeouts or not
            ctime = time()
            duration = ctime - stime
            if duration >= config_info['local_timeout']:  # exit if timeouts
                logging.debug(f"[R-{round_no}-{subround_no}] Timeout locally!"
					f"-> Duration: {duration} ({ctime} - {stime}) in seconds")
                break
            # check whether all the locations get explored or not.
            unexplore_loc_idx_list = np.where(np.asarray(
                [len(item) for item in sens_map.loc_map()['value']]) == 0)[0]
            logging.debug(
                f"[R-{round_no}-{subround_no}] #(Unexplored Locs): {len(unexplore_loc_idx_list)}")
            if len(unexplore_loc_idx_list) == 0:
                logging.debug(f"[R-{round_no}-{subround_no}] Finish exploring all the locs!")
                break

        # (YN: skipped processing and saving of sensitivity map to save time)
        # sens_map.save_maps_to_disk(selected_seed_trace_hash)

        # check the global timeout
        ctime = time()
        duration = ctime - stime
        if duration >= config_info['global_timeout']:
            logging.debug(f"[R-{round_no}] Timeout!"
				f"-> Duration: {duration} ({ctime} - {stime}) in seconds")
            break


def save_useful_info():
    report_filepath = os.path.join(values.OutFolder, 'reports.pkl')
    utils.write_pkl(report_filepath, values.ReportCollection)
    logging.debug("Finish writing all the reports!")

    seed_filepath = os.path.join(values.OutFolder, 'seeds.pkl')
    utils.write_pkl(seed_filepath, values.SeedPool)
    logging.debug("Finish writing all the seeds!")

    seed_hash_filepath = os.path.join(values.OutFolder, 'seed_hashes.pkl')
    utils.write_pkl(seed_hash_filepath, values.SeedTraceHashList)
    logging.debug("Finish writing all the hash of seeds!")


def concentrate_fuzz(config_info):
    # (YN: added some info output)
    logging.info(f"Input format: {config_info['input_format']}")
    logging.info(f"Store all input files: {config_info['store_all_inputs']}")

    values.StoreAllInputs = config_info['store_all_inputs']

    # init the randomization function
    np.random.seed(config_info['rand_seed'])
    logging.info(f"Initialized the random seed -> {config_info['rand_seed']}")

    # prepare different binaries
    tracer.rewrite_trace_binary(config_info['bin_path'])
    oracle.rewrite_binary_with_oracle(config_info['bin_path'])

    trace, seed_len = process_poc(config_info)

    real_concfuzz_loop(config_info, trace, seed_len)

    # (YN: skipped to save time due not needed)
    save_useful_info()

    logging.debug('Done!')


if __name__ == '__main__':
    tag, parsed_config_info, verbose = parse_args()
    init_log(tag, verbose, parsed_config_info)
    concentrate_fuzz(parsed_config_info)
