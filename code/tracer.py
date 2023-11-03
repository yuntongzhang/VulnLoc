import hashlib
import os
import subprocess
import sys
from typing import List, Tuple

import values


class TraceEntry(object):
    """
    Represent one entry in a trace.
    """

    def __init__(self, addr: str, labels: List[Tuple[int, int]] = []):
        self.addr: str = addr
        # a list of labels, where each label is a tuple with 2 int
        # (x, y), where x represents the condense len, and y represents the repeat count
        self.labels: List[Tuple[int, int]] = labels

    def __eq__(self, other):
        if not isinstance(other, TraceEntry):
            return False
        return self.addr == other.addr and self.labels == other.labels

    def __str__(self):
        return f"{self.addr} ({self.labels})"


class LoopRepeatInfo(object):
    """
    Represent information related to one loop repeat pattern.
    """

    def __init__(self, start_idx: int, count: int, size: int):
        # where this repetition pattern starts
        self.start_idx: int = start_idx
        # how many times this repetition pattern repeats
        self.count: int = count
        # how many elements are there in one repeat
        self.size: int = size


def find_repeated_seq_with_length(
    lst: List[TraceEntry], length: int
) -> List[LoopRepeatInfo]:
    """
    In lst, find consecutively repeated sequence of length 'length',
    and condense them into one single occurence.
    """
    res: List[LoopRepeatInfo] = []  # (rep_start_idx, rep_count, rep_size)

    if len(lst) <= length:
        return res  # dont bother

    curr_repeat_start = -1
    curr_repeat_count = 1

    i = length
    while i + length <= len(lst):
        # curr_ele = lst[i]
        if lst[i : i + length] == lst[i - length : i]:
            # print(f"Found two same windows: {lst[i:i+length]} and {lst[i-length:i]}")
            # curr window is a repeat of previous window
            if curr_repeat_start == -1:
                # this is the first time we see a repeat of this kind
                curr_repeat_start = i - length
            curr_repeat_count += 1
            # if we found a repeat, advance by window size
            i += length
        else:
            # curr window is NOT a repeat of previous window
            # check whether we have a repeat session
            if curr_repeat_start != -1:
                # in a repeat session
                # dump the current session result
                new_rep_info = LoopRepeatInfo(
                    curr_repeat_start, curr_repeat_count, length
                )
                res.append(new_rep_info)
                # reset the repeat session
                curr_repeat_start = -1
                curr_repeat_count = 1
                # if prev window is in a repeat session, we should not even look at it again later
                i += length
            else:
                # advance by one
                i += 1
    return res


def condense_trace(
    trace: List[TraceEntry], rep_info: List[LoopRepeatInfo]
) -> List[TraceEntry]:
    res = []
    trace_idx_processed = 0
    for info in rep_info:
        rep_start = info.start_idx
        rep_count = info.count
        rep_size = info.size
        # add the prefix
        res += trace[trace_idx_processed:rep_start]
        # condense repeated sequence in the middle
        condensed = []
        for i in range(rep_size):
            # create a new trace entry
            old_addr = trace[rep_start + i].addr
            old_labels = trace[rep_start + i].labels
            new_labels = old_labels + [(rep_size, rep_count)]
            new_entry = TraceEntry(old_addr, new_labels)
            condensed.append(new_entry)
        res += condensed
        # res += trace[trace_idx_processed:rep_start+rep_size]
        # update cursor
        trace_idx_processed = rep_start + rep_count * rep_size

    # add the tail without repeat sequences
    res += trace[trace_idx_processed:]
    return res


def postprocess_trace(trace: List[TraceEntry], loop_size_limit=10):
    """
    Identify loops in the trace (up to the given size), and condense them.
    """
    # max_condense_len = 10
    # print(f"Len of the original trace (before condensation): {len(trace)}")

    updated_trace = trace
    for i in range(1, loop_size_limit+1):
        rep_info = find_repeated_seq_with_length(updated_trace, i)
        # print(f"Size of rep_info for condense length {i}： {len(rep_info)}")
        updated_trace = condense_trace(updated_trace, rep_info)

    # print(f"Len of updated trace (after {loop_size_limit} condensations): {len(updated_trace)}")
    return updated_trace


def rewrite_trace_binary(bin_path):
    """
    Rewritten binary is named as bin.trace
    """
    trace_bin_path = bin_path + ".trace"
    curr_dir = os.getcwd()
    os.chdir(values.e9patch_dir)
    patch_cmd = [
        "./e9tool",
        "-M",
        "BB.entry",
        "-P",
        "entry((static)addr)@printaddr",
        "-o",
        trace_bin_path,
        bin_path,
    ]
    p = subprocess.Popen(patch_cmd)
    p.communicate()
    if not os.path.isfile(trace_bin_path):
        sys.exit("Failed to use e9patch to create trace binary. Aborting ...")
    os.chdir(curr_dir)


def exec_bin(cmd_list, bin_path) -> List[TraceEntry]:
    """
    Execute the binary for tracing, and return the obtained trace.
    """
    trace_bin_path = bin_path + ".trace"
    cmd_list = [trace_bin_path if s == bin_path else s for s in cmd_list]
    p = subprocess.Popen(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    )
    _, err = p.communicate()
    # parse output (stderr)
    trace: List[TraceEntry] = []
    for line in err.split("\n"):
        if not line.startswith("0x"):
            continue
        new_entry = TraceEntry(line.strip())
        trace.append(new_entry)
    # process raw trace by condensing it
    trace = postprocess_trace(trace)
    return trace


def calc_trace_hash(trace: List[TraceEntry]):
    trace_str = "\n".join(str(trace))
    return hashlib.sha256(trace_str.encode("utf-8")).hexdigest()


def trace_cmp(seed_trace: List[TraceEntry], trace: List[TraceEntry]):
    """
    Compare two traces, and return the idx where they diverge.
    """
    min_len = min(len(seed_trace), len(trace))
    for idx in range(min_len):
        if seed_trace[idx] != trace[idx]:
            return idx
    return min_len


def dynamorio_exec_bin(cmd_list):
    # craft tracing command
    tracer_cmd_list = [values.dynamorio_path, "-c", values.iftracer_path, "--"]
    tracer_cmd_list.extend(cmd_list)
    # execute command
    p1 = subprocess.Popen(
        tracer_cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    )
    out, _ = p1.communicate()
    # parse the output
    if_list = []
    for aline in out.split("\n"):
        if "0x00000000004" in aline:
            t = aline.split(" => ")
            if_list.append(t[0])
    return if_list
