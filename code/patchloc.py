import os
import string
import subprocess
from multiprocessing import Pool
import numpy as np

import utils
import values
import logger


def process_poc_trace():
    tmp = np.load(values.PocTracePath)
    poc_trace = tmp['trace']
    poc_trace = np.asarray(poc_trace)
    return poc_trace


def read_single_trace(file_name, file_no):
    if file_no % 100 == 0:
        print(f'Reading {file_no}_th trace')
    file_path = os.path.join(values.TraceFolder, file_name)

    tmp = np.load(file_path)
    content = tmp['trace']
    trace_hash = file_name.split('.')[0]

    unique_insns = np.unique(np.asarray(content))
    return [trace_hash, unique_insns]


def init_count_dict(valid_insns):
    count_dict = {}
    for insn in valid_insns:
        count_dict[insn] = 0
    return count_dict


def read_all_reports():
    file_list = os.listdir(values.TraceFolder)
    file_num = len(file_list)
    trace_collection = []
    pool = Pool(utils.get_process_num())
    for file_no in range(file_num):
        pool.apply_async(
            read_single_trace,
            args=(file_list[file_no], file_no),
            callback=trace_collection.append
        )
    pool.close()
    pool.join()
    print('Finish reading all the traces')
    trace_dict = {}
    for item in trace_collection:
        trace_dict[item[0]] = item[1]
    # read reports
    reports = utils.read_pkl(values.SavedReportPath)
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
        logger.I('max_value == min_value in normalization')
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
    logger.I(f"#reports: {malicious_num + benign_num} "
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
    unknown_str = "UNKNOWN"
    line_num = len(assembly)
    target_insn = insn[-6:] + ':'
    target_line_no = -1
    for line_no in range(line_num):
        line = assembly[line_no].split()
        if len(line) > 0 and line[0] == target_insn:
            target_line_no = line_no
            break
    if target_line_no < 0:
        logger.D(f"ERROR: Cannot find the instruction -> {insn}")
        return unknown_str
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
    logger.D(f"Cannot find the source code for instruction -> {insn}")
    return unknown_str


def rank():
    # process the poc trace
    poc_trace = process_poc_trace()
    unique_insn = np.unique(poc_trace)
    # read all the important files
    trace_dict, report_dict = read_all_reports()
    # count
    valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore = count_all(
        unique_insn, report_dict, trace_dict, values.VarRankingPath)
    return poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore


def show(assembly, poc_trace, valid_insns, group_info, l2_norm, normalized_nscore,
        normalized_sscore):
    group_num = len(group_info)
    show_no = 0
    for group_no in range(group_num):
        insn_id_list = np.asarray(group_info[group_no])
        insns = valid_insns[insn_id_list]
        distance_list = calc_distance(poc_trace, insns)
        sorted_idx_list = np.argsort(-np.asarray(distance_list))
        sorted_insn_id_list = insn_id_list[sorted_idx_list]

        for insn_id in sorted_insn_id_list:
            logger.I(f"[INSN-{show_no}] {valid_insns[insn_id]} ->"
                f"{insn_to_src(assembly, valid_insns[insn_id])} "
                f"(l2norm: {l2_norm[insn_id]}; normalized(N): {normalized_nscore[insn_id]};"
                f"normalized(S): {normalized_sscore[insn_id]})")
            show_no += 1
            if show_no >= values.ShowNum:
                break
        if show_no >= values.ShowNum:
            break


def check_required_data_and_setup():
    if not os.path.exists(values.TraceFolder):
        raise Exception(f"ERROR: Unknown folder -> {values.TraceFolder}")

    if not os.path.exists(values.PocTracePath):
        raise Exception(f"ERROR: Unknown file path -> {values.PocTracePath}")

    if not os.path.exists(values.SavedReportPath):
        raise Exception(f"ERROR: Unknown file path -> {values.SavedReportPath}")

    values.VarRankingPath = os.path.join(values.OutFolder, 'var_ranking.npz')


def rank_locations(config_info):
    asm = bin_to_asm(config_info['bin_path'])

    if values.PatchLocFunc == 'calc':
        poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore = rank()

        show(asm, poc_trace, valid_insns, group_info, l2_norm, normalized_nscore, normalized_sscore)

    elif values.PatchLocFunc == 'show':
        # process the poc trace
        poc_trace = process_poc_trace()

        if not os.path.exists(values.VarRankingPath):
            raise Exception(f"ERROR: The .npz file does not exist -> {values.VarRankingPath}")
        info = np.load(values.VarRankingPath, allow_pickle=True)

        show(asm, poc_trace, info['insns'], info['group_idx'], info['l2_norm'],
             info['normalized_nscore'], info['normalized_sscore'])

    else:
        raise Exception(f"ERROR: Function {values.PatchLocFunc} does not exist")


def run(parsed_config):
    """
    Main entry for the localization phase.
    """
    check_required_data_and_setup()
    logger.init_patchloc_log()
    rank_locations(parsed_config)
