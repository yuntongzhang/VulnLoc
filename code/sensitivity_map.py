import itertools
import numpy as np
import logging
import os

import values
import utils


class SensMap(object):
    def __init__(self, seed_len, seed_trace_len, max_combination):
        idx_list = []
        for comb_id in range(1, max_combination + 1):
            tmp = list(itertools.combinations(range(seed_len), comb_id))
            if len(tmp) > (values.MaxCombineNum - len(idx_list)):
                np.random.shuffle(tmp)
                idx_list += tmp[:values.MaxCombineNum - len(idx_list)]
                break
            else:
                idx_list += tmp

        logging.debug(f"Max Combinations: {max_combination}")
        logging.debug(f"Number of Mutation Idxes: {len(idx_list)}")
        logging.debug(f"#Loc: {seed_trace_len}")
        logging.debug(f"Size(seed): {seed_len}")

        self.crash_sens_map = {
            'idx': idx_list,
            'value': np.zeros(len(idx_list))
        }
        self.loc_sens_map = {
            'idx': idx_list,
            'tag': np.zeros(len(idx_list)),
            'value': [[] for _ in range(seed_trace_len)]
	    }
        self.seed_len = seed_len
        self.max_combination = max_combination


    def update_maps(self, mutate_idx, diff_collection, crash_collection):
        self.update_loc_map(mutate_idx, diff_collection)
        self.update_crash_map(mutate_idx, crash_collection)


    def update_loc_map(self, mutate_idx, diff_collection):
        loc_num = len(self.loc_sens_map['value'])
        for diff_id in diff_collection:
            if diff_id < loc_num:
                logging.debug(f"Update location sensitivity map! loc: {diff_id}; mutate id: {mutate_idx}")
                self.loc_sens_map['value'][diff_id].append(mutate_idx)


    def update_crash_map(self, mutate_idx, crash_collection):
        if len(crash_collection) == 2:
            logging.debug(f"Update crash location sensitivity map! mutate id: {mutate_idx}")
            self.crash_sens_map['value'][mutate_idx] = 1


    def select_mutate_idx(self):
        # select the non-mutated bytes
        non_mutated_idx = np.where(self.loc_sens_map['tag'] == 0)[0]
        # find out which loc has not been explored
        unexplore_list = np.where(np.asarray([len(item) for item in self.loc_sens_map['value']]) == 0)[0]
        logging.debug(f"#(unexplored loc): {len(unexplore_list)}")
        if len(unexplore_list) == 0:
            return None
        unexplore_loc_id = np.min(unexplore_list)
        logging.debug(f"Unexplored Loc ID: {unexplore_loc_id}")

        tmp = []
        for item in self.loc_sens_map['value'][:unexplore_loc_id]:
            tmp += item
        fixed_idx = np.asarray(list(set(tmp)))
        logging.debug(f"Fixed IDs: {fixed_idx}")

        # find out the bytes that can be mutated
        non_mutated_idx = np.asarray(list(set(non_mutated_idx) - set(fixed_idx)))
        logging.debug(f"#(potential idxes): {len(non_mutated_idx)}")

        # randomly select one idx from non_mutated_idx
        min_idx = 0
        idx_range = []
        for comb_id in range(1, self.max_combination + 1):
            max_idx = min_idx + len(list(itertools.combinations(range(self.seed_len), comb_id)))
            idx_range += list(non_mutated_idx[np.where(np.logical_and(non_mutated_idx >= min_idx, non_mutated_idx<max_idx))[0]])
            min_idx = max_idx
            if len(idx_range) > 0:
                logging.debug(f"Select the mutation idx from {comb_id}-combination")
                np.random.shuffle(idx_range)
                return idx_range[0]
        return None


    def mark_mutate_idx(self, mutate_idx):
        self.loc_sens_map['tag'][mutate_idx] = 1

    def retrieve_mutate_idx(self, mutate_idx):
        return self.loc_sens_map['idx'][mutate_idx]


    def loc_map(self):
        return self.loc_sens_map


    def crash_map(self):
        return self.crash_sens_map


    def save_maps_to_disk(self, seed_trace_hash):
        # processing the local sensitivity (for saving the hard disk)
        loc_sens = []
        loc_idxes = []
        loc_num = len(self.loc_sens_map['value'])
        for loc_id in range(loc_num):
            if len(self.loc_sens_map['value'][loc_id]) > 0:
                loc_idxes.append(loc_id)
                loc_sens.append(self.loc_sens_map['value'][loc_id])
        loc_sens = []
        loc_idxes = []
        loc_num = len(self.loc_sens_map['value'])
        for loc_id in range(loc_num):
            tmp = np.where(self.loc_sens_map['value'][loc_id]>0)[0]
            if len(tmp) > 0:
                loc_idxes.append(loc_id)
                loc_sens.append(tmp)

        # save the sensitivity map
        sensitivity_filepath = os.path.join(values.OutFolder, f'sensitivity_{seed_trace_hash}.pkl')
        logging.debug("Start saving the sensitivity map -> {sensitivity_filepath}")
        info = {
            'idx': self.loc_sens_map['idx'],
            'loc_idx': loc_idxes,
            'loc_sens': loc_sens,
            'crash_sens': list(self.crash_sens_map['value']),
            'loc_tag': list(self.loc_sens_map['tag'])
        }
        utils.write_pkl(sensitivity_filepath, info)
        logging.debug(f"Finish writing the sensitivity map -> {sensitivity_filepath}")
