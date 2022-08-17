import argparse
import os
import string
import logging
import subprocess
import configparser
from multiprocessing import Pool

import numpy as np
import parse_dwarf

import utils


def process_poc_trace(poc_trace_path, bin_path, target_src_str, load_from_npz):
    if load_from_npz:
        tmp = np.load(poc_trace_path)
        poc_trace = tmp['trace']
    else:
        poc_trace = utils.read_pkl(poc_trace_path)
    poc_trace = np.asarray(poc_trace)
    if len(target_src_str) == 0:
        return poc_trace
    else:
        insn_list = parse_dwarf.get_bin_line(bin_path, target_src_str)
        insn_idx_list = []
        for insn in insn_list:
            insn_idx_list += list(np.where(poc_trace == insn)[0])
        if len(insn_idx_list) == 0:
            raise Exception(f"ERROR: Cannot find the instructions for source -> {target_src_str}")
        max_id = max(insn_idx_list)
        return poc_trace[:max_id+1]


def read_single_trace(folder_path, file_name, file_no, load_from_npz):
    if file_no % 100 == 0:
        print(f'Reading {file_no}_th trace')
    file_path = os.path.join(folder_path, file_name)
    if load_from_npz:
        tmp = np.load(file_path)
        content = tmp['trace']
        trace_hash = file_name.split('.')[0]
    else:
        content = utils.read_pkl(file_path)
        trace_hash = file_name
    unique_insns = np.unique(np.asarray(content))
    temp = [trace_hash, unique_insns]
    return temp


def init_count_dict(valid_insns):
    count_dict = {}
    for insn in valid_insns:
        count_dict[insn] = 0
    return count_dict


def read_all_reports(report_file, trace_folder, process_num, load_from_npz):
    file_list = os.listdir(trace_folder)
    file_num = len(file_list)
    trace_collection = []
    pool = Pool(process_num)
    for file_no in range(file_num):
        pool.apply_async(
            read_single_trace,
            args=(trace_folder, file_list[file_no], file_no, load_from_npz),
            callback=trace_collection.append
        )
    pool.close()
    pool.join()
    print('Finish reading all the traces')
    trace_dict = {}
    for item in trace_collection:
        trace_dict[item[0]] = item[1]
    # read reports
    reports = utils.read_pkl(report_file)
    # split reports
    report_dict = {
        'm': [], 'b': []
    }
    for item in reports:
        report_dict[item[1]].append(item[0])
    print('Finish splitting the reports into two categories!')
    return trace_dict, report_dict


def count(report_list, dest_dict, trace_dict):
    target_insn_set = set(dest_dict.keys())
    for trace_hash in report_list:
        intersect_set = set(trace_dict[trace_hash]) & target_insn_set
        for insn in intersect_set:
            dest_dict[insn] += 1


def normalize_score(score):
    max_value = np.max(score)
    min_value = np.min(score)
    if max_value == min_value:
        logging.info('max_value == min_value in normalization')
        return score
    else:
        normalized_score = (score - min_value) / (max_value - min_value)
        return normalized_score


def group_scores(scores):
    insn_num = len(scores)
    group_info = []
    group_value = -1
    group_list = []
    for insn_no in range(insn_num):
        if group_value < 0:
            group_value = scores[insn_no]
            group_list.append(insn_no)
        else:
            if group_value == scores[insn_no]:
                group_list.append(insn_no)
            else:
                group_info.append(group_list)
                group_list = [insn_no]
                group_value = scores[insn_no]
    group_info.append(group_list)
    return group_info


def calc_scores(valid_insns, tc_num_dict, t_num_dict, malicious_num, output_path):
    tc_num_list = np.asarray([tc_num_dict[insn] for insn in valid_insns], dtype=np.float)
    t_num_list = np.asarray([t_num_dict[insn] for insn in valid_insns], dtype=np.float)
    n_score = tc_num_list / float(malicious_num)
    s_score = tc_num_list / t_num_list
    normalized_nscore = normalize_score(n_score)
    normalized_sscore = normalize_score(s_score)
    l2_norm = np.sqrt(normalized_nscore ** 2 + normalized_sscore ** 2)
    print('Calculated all the scores!')
    sorted_idx_list = np.argsort(-l2_norm)
    # sorting all the insns
    valid_insns = valid_insns[sorted_idx_list]
    tc_num_list = tc_num_list[sorted_idx_list]
    t_num_list = t_num_list[sorted_idx_list]
    n_score = n_score[sorted_idx_list]
    s_score = s_score[sorted_idx_list]
    normalized_nscore = normalized_nscore[sorted_idx_list]
    normalized_sscore = normalized_sscore[sorted_idx_list]
    l2_norm = l2_norm[sorted_idx_list]
    print('Sorted all the scores')
    # group the insns according to its score
    group_info = group_scores(l2_norm)
    np.savez(output_path,
             insns=valid_insns, tc_num=tc_num_list, t_num=t_num_list,
             nscore=n_score, sscore=s_score,
             normalized_nscore=normalized_nscore, normalized_sscore=normalized_sscore,
             l2_norm=l2_norm, group_idx=group_info)
    return valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore


def count_all(valid_insns, report_dict, trace_dict, output_path):
    malicious_num = len(report_dict['m'])
    benign_num = len(report_dict['b'])
    logging.info(f"#reports: {malicious_num + benign_num} "
        f"(#malicious: {malicious_num}; #benign: {benign_num})")
    # initialize all the count info
    tc_num_dict = init_count_dict(valid_insns)
    t_num_dict = init_count_dict(valid_insns)
    # count number(t_i & c)
    count(report_dict['m'], tc_num_dict, trace_dict)
    count(report_dict['m'] + report_dict['b'], t_num_dict, trace_dict)
    valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore = calc_scores(
        valid_insns, tc_num_dict, t_num_dict, malicious_num, output_path)
    return valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore


def rank(poc_trace_path, bin_path, target_src_str, report_file, trace_folder,
        process_num, npz_path, load_from_npz):
    # process the poc trace
    poc_trace = process_poc_trace(poc_trace_path, bin_path, target_src_str, load_from_npz)
    unique_insn = np.unique(poc_trace)
    # read all the important files
    trace_dict, report_dict = read_all_reports(report_file, trace_folder,
        process_num, load_from_npz)
    # count
    valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore = count_all(
        unique_insn, report_dict, trace_dict, npz_path)
    return poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore


def calc_distance(poc_trace, insns):
    distance_list = []
    for insn in insns:
        distance_list.append(
            np.max(np.where(poc_trace == insn)[0])
        )
    return distance_list


def bin_to_asm(bin_path):
    cmd_list = ['objdump', '-S', '-l', bin_path]
    p1 = subprocess.Popen(cmd_list, encoding='utf-8', errors='replace',
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = p1.communicate()
    content = out.split('\n')
    return content


def insn_to_src(assembly, insn):
    line_num = len(assembly)
    target_insn = insn[-6:] + ':'
    target_line_no = -1
    for line_no in range(line_num):
        line = assembly[line_no].split()
        if len(line) > 0 and line[0] == target_insn:
            target_line_no = line_no
            break
    if target_line_no < 0:
        raise Exception(f"ERROR: Cannot find the instruction -> {insn}")
    while target_line_no >= 0:
        line = assembly[target_line_no]
        tmp = line.split()
        if len(tmp) >= 1 and ':' in tmp[0]:
            tmp2 = tmp[0].split(':')
            tag = True
            for tmp3 in tmp2[1]:
                if tmp3 not in string.digits:
                    tag = False
                    break
            if os.path.exists(tmp2[0]) and tag:
                return tmp[0].split('/')[-1]
        target_line_no = target_line_no - 1
    logging.info(f"Cannot find the source code for instruction -> {insn}")
    return "UNKNOWN"


def show(assembly, poc_trace, valid_insns, group_info, l2_norm, normalized_nscore,
        normalized_sscore, show_num):
    group_num = len(group_info)
    show_no = 0
    for group_no in range(group_num):
        insn_id_list = np.asarray(group_info[group_no])
        insns = valid_insns[insn_id_list]
        distance_list = calc_distance(poc_trace, insns)
        sorted_idx_list = np.argsort(-np.asarray(distance_list))
        sorted_insn_id_list = insn_id_list[sorted_idx_list]

        for insn_id in sorted_insn_id_list:
            logging.info(f"[INSN-{show_no}] {valid_insns[insn_id]} ->"
                f"{insn_to_src(assembly, valid_insns[insn_id])} "
                f"(l2norm: {l2_norm[insn_id]}; normalized(N): {normalized_nscore[insn_id]};"
                f"normalized(S): {normalized_sscore[insn_id]})")
            show_no += 1
            if show_no >= show_num:
                break
        if show_no >= show_num:
            break


def parse_args():
    parser = argparse.ArgumentParser(description="PatchLoc")
    parser.add_argument("--config", dest="config", type=str, required=True,
                        help="The path of config file")
    parser.add_argument("--tag", dest="tag", type=str, required=True,
                        help="The cve tag")
    parser.add_argument("--func", dest="func", type=str, required=True,
                        help="The function for execution (calc/show)")
    parser.add_argument("--out", dest="out_folder", type=str, required=True,
                        help="The path of output folder which is named according to the timestamp")
    parser.add_argument("--poc_trace_hash", dest="poc_trace_hash", type=str, required=True,
                        help="The hash of executing trace of poc")
    parser.add_argument("--target_src_str", dest="target_src_str", type=str, default="",
                        help="The source line at the crash location")
    parser.add_argument("--process_num", dest="process_num", type=int, default=10,
                        help="The number of processes")
    parser.add_argument("--show_num", dest="show_num", type=int, default=10,
                        help="The number of instructions to show")
    args = parser.parse_args()

    out_folder = args.out
    config = configparser.ConfigParser()
    config.read(args.config)
    if args.tag not in config.sections():
        raise Exception(f"ERROR: Please provide the configuration file for {args.tag}")

    detailed_config = {}
    for item in config.items(args.tag):
        if item[0] == 'folder':
            if not os.path.exists(item[1]):
                raise Exception(f"ERROR: The folder does not exist -> {item[1]}")
            detailed_config[item[0]] = item[1]
        else:
            detailed_config[item[0]] = item[1].split(';')

    if 'bin_path' in detailed_config:
        bin_path = detailed_config['bin_path'][0]
        if not os.path.exists(bin_path):
            raise Exception(f"ERROR: Binary file does not exist -> {bin_path}")
        detailed_config['bin_path'] = bin_path
    else:
        raise Exception("ERROR: Please specify the binary file in config.ini")

    trace_folder = os.path.join(out_folder, 'traces')
    if not os.path.exists(trace_folder):
        raise Exception(f"ERROR: Unknown folder -> {trace_folder}")
    detailed_config['trace_folder'] = trace_folder

    poc_trace_path = os.path.join(trace_folder, args.poc_trace_hash)
    if not os.path.exists(poc_trace_path):
        poc_trace_path = poc_trace_path + '.npz'
        detailed_config['load_from_npz'] = False
        if not os.path.exists(poc_trace_path):
            raise Exception(f"ERROR: Unknown file path -> {poc_trace_path}")
        else:
            detailed_config['load_from_npz'] = True
    detailed_config['poc_trace_path'] = poc_trace_path

    report_file = os.path.join(out_folder, 'reports.pkl')
    if not os.path.exists(report_file):
        raise Exception(f"ERROR: Unknown file path -> {report_file}")
    detailed_config['report_file'] = report_file

    npz_path = os.path.join(out_folder, 'var_ranking.npz')
    detailed_config['npz_path'] = npz_path

    return (args.func, args.target_src_str, detailed_config, args.process_num,
            args.show_num, out_folder)


def init_log(out_folder):
    log_path = os.path.join(out_folder, 'patchloc.log')
    logging.basicConfig(filename=log_path, filemode='a+', level=logging.DEBUG,
                        format="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s",
                        datefmt="%d-%b-%y %H:%M:%S")
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter(fmt="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s",
                                    datefmt="%d-%b-%y %H:%M:%S")
    console.setFormatter(console_fmt)
    logging.getLogger().addHandler(console)
    logging.info(f"Output Folder: {out_folder}")


def controller(tag, target_src_str, config_info, process_num, show_num):
    asm = bin_to_asm(config_info['bin_path'])

    if tag == 'calc':
        poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore = rank(
            config_info['poc_trace_path'], config_info['bin_path'], target_src_str,
            config_info['report_file'], config_info['trace_folder'], process_num,
            config_info['npz_path'], config_info['load_from_npz'])

        show(asm, poc_trace, valid_insns, group_info,
             l2_norm, normalized_nscore, normalized_sscore, show_num)

    elif tag == 'show':
        # process the poc trace
        poc_trace = process_poc_trace(config_info['poc_trace_path'], config_info['bin_path'],
            target_src_str, config_info['load_from_npz'])

        if not os.path.exists(config_info['npz_path']):
            raise Exception(f"ERROR: The .npz file does not exist -> {config_info['npz_path']}")
        info = np.load(config_info['npz_path'], allow_pickle=True)

        show(asm, poc_trace, info['insns'], info['group_idx'], info['l2_norm'],
             info['normalized_nscore'], info['normalized_sscore'], show_num)

    else:
        raise Exception(f"ERROR: Function tag does not exist -> {tag}")


def main():
    tag, target_src_str, config_info, process_num, show_num, out_folder = parse_args()
    init_log(out_folder)
    controller(tag, target_src_str, config_info, process_num, show_num)


if __name__ == '__main__':
    main()
