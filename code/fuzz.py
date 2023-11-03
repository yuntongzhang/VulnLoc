import os
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
import logger
from sensitivity_map import SensMap


def setup_folders(outer_folder):
    values.OutFolder = os.path.join(outer_folder, 'fuzzer')

    if os.path.exists(values.OutFolder):
        raise Exception(f"ERROR: Output folder already exists! -> {values.OutFolder}")

    os.mkdir(values.OutFolder)

    values.ConcentratedInputFolder = os.path.join(values.OutFolder, 'concentrated_inputs')
    if not os.path.exists(values.ConcentratedInputFolder):
        os.mkdir(values.ConcentratedInputFolder)
    values.AllInputFolder = os.path.join(values.OutFolder, 'all_inputs')
    if not os.path.exists(values.AllInputFolder):
        os.mkdir(values.AllInputFolder)

    values.TmpFolder = os.path.join(values.OutFolder, 'tmp')
    if not os.path.exists(values.TmpFolder):
        os.mkdir(values.TmpFolder)

    values.TraceFolder = os.path.join(values.OutFolder, 'traces')
    if not os.path.exists(values.TraceFolder):
        os.mkdir(values.TraceFolder)


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
    logger.I(f"write input: {input_filepath}")
    if config_info['input_format'] == 'bfile':
        utils.write_bin(input_filepath, content)
    else:  # == 'text'
        utils.write_txt(input_filepath, json.dumps(list(content)))
    input_counter += 1
    return input_counter


def process_poc(config_info):
    """
    Generate trace for the poc input.
    """
    trace, trace_hash = runner.just_trace(0, config_info['poc'], config_info['poc_fmt'],
            config_info['trace_cmd'], config_info['trace_replace_idx'], config_info['bin_path'])
    logger.D(f'PoC Hash: {trace_hash}')
    seed_len = len(config_info['poc'])
    # save the trace
    values.TraceHashCollection.append(trace_hash)
    path = os.path.join(values.TraceFolder, trace_hash)
    # utils.write_pkl(path, trace)
    np.savez(path, trace=trace)
    values.PocTracePath = path + ".npz"
    # add the report
    values.ReportCollection.append([trace_hash, 'm'])
    # add into seed pool
    values.SeedPool.append([False, config_info['poc']])
    values.SeedTraceHashList.append(trace_hash)
    logger.I('Finish processing the poc!')
    return trace, seed_len


def real_concfuzz_loop(config_info, poc_trace, seed_len):
    stime = time()  # starting time
    round_no = 0
    while True:
        round_no += 1
        # choose seed & load seed_trace
        selection_result = choose_seed()
        if selection_result is None:
            logger.D(f"[R-{round_no}] Finish processing all the seeds!")
            break
        selected_seed_trace_hash, selected_seed = selection_result
        logger.D(f"[R-{round_no}] Select seed -> {selected_seed_trace_hash}")
        seed_pool_str = '\n'.join([f'{values.SeedTraceHashList[id]}: {values.SeedPool[id][0]}'
                                   for id in range(len(values.SeedPool))])
        logger.D(f"The status of current seed pool:\n{seed_pool_str}")

        trace_path = os.path.join(values.TraceFolder, selected_seed_trace_hash + '.npz')
        if round_no == 1:
            selected_seed_trace = poc_trace
        else:
            selected_seed_trace = np.load(trace_path)
            # selected_seed_trace = utils.read_pkl(trace_path)
        logger.I(f'len(Seed Trace): {len(selected_seed_trace)}')

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
            logger.D(f"[R-{round_no}-{subround_no}] Select the mutate idx ->"
			 	f"{mutate_idx}: {actual_mutate_loc}")
            sens_map.mark_mutate_idx(mutate_idx)
            # mutate inputs
            inputs = mutate_inputs(selected_seed, config_info['poc_fmt'],
								   config_info['#mutation'], actual_mutate_loc)
            logger.D(f"Shape(mutated_inputs): {inputs.shape}")
            # execute all the mutated inputs
            # each element is in the fmt of [id, trace, trace_hash, crash_result, trace_diff_id]
            result_collection = []
            input_num = len(inputs)
            pool = Pool(utils.get_process_num())
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
            logger.D(f"#(Missed): {input_num - len(result_collection)}")
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

            logger.D(f"#Diff: {len(diff_collection)}; #ExeResult: {len(crash_collection)};"
				f"#seed: {len(values.SeedPool)}")

            # update sensitivity map
            sens_map.update_maps(mutate_idx, diff_collection, crash_collection)
            # check whether it timeouts or not
            ctime = time()
            duration = ctime - stime
            if duration >= config_info['local_timeout']:  # exit if timeouts
                logger.D(f"[R-{round_no}-{subround_no}] Timeout locally!"
					f"-> Duration: {duration} ({ctime} - {stime}) in seconds")
                break
            # check whether all the locations get explored or not.
            unexplore_loc_idx_list = np.where(np.asarray(
                [len(item) for item in sens_map.loc_map()['value']]) == 0)[0]
            logger.D(
                f"[R-{round_no}-{subround_no}] #(Unexplored Locs): {len(unexplore_loc_idx_list)}")
            if len(unexplore_loc_idx_list) == 0:
                logger.D(f"[R-{round_no}-{subround_no}] Finish exploring all the locs!")
                break

        # (YN: skipped processing and saving of sensitivity map to save time)
        # sens_map.save_maps_to_disk(selected_seed_trace_hash)

        # check the global timeout
        ctime = time()
        duration = ctime - stime
        if duration >= config_info['global_timeout']:
            logger.D(f"[R-{round_no}] Timeout!"
				f"-> Duration: {duration} ({ctime} - {stime}) in seconds")
            break


def save_useful_info():
    values.SavedReportPath = os.path.join(values.OutFolder, 'reports.pkl')
    utils.write_pkl(values.SavedReportPath, values.ReportCollection)
    logger.D("Finish writing all the reports!")

    values.SavedSeedsPath = os.path.join(values.OutFolder, 'seeds.pkl')
    utils.write_pkl(values.SavedSeedsPath, values.SeedPool)
    logger.D("Finish writing all the seeds!")

    values.SavedSeedHashesPath = os.path.join(values.OutFolder, 'seed_hashes.pkl')
    utils.write_pkl(values.SavedSeedHashesPath, values.SeedTraceHashList)
    logger.D("Finish writing all the hash of seeds!")


def concentrate_fuzz(config_info):
    # (YN: added some info output)
    logger.I(f"Input format: {config_info['input_format']}")
    logger.I(f"Store all input files: {config_info['store_all_inputs']}")

    values.StoreAllInputs = config_info['store_all_inputs']

    # init the randomization function
    np.random.seed(config_info['rand_seed'])
    logger.I(f"Initialized the random seed -> {config_info['rand_seed']}")

    # prepare different binaries
    tracer.rewrite_trace_binary(config_info['bin_path'])
    oracle.rewrite_binary_with_oracle(config_info['bin_path'])

    trace, seed_len = process_poc(config_info)

    real_concfuzz_loop(config_info, trace, seed_len)

    # (YN: skipped to save time due not needed)
    save_useful_info()

    logger.D('Done!')


def run(parsed_config):
    """
    Main entry for the fuzzing phase.
    """
    setup_folders(parsed_config['folder'])
    logger.init_fuzz_log(parsed_config)
    concentrate_fuzz(parsed_config)
