from typing import List, Tuple

class TraceEntry(object):
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



def read_trace(fname: str) -> List[TraceEntry]:
    
    with open(fname, "r") as f:
        trace = f.readlines()

    final: List[TraceEntry] = []
    for t in trace:
        a = t.strip().split("=>")[0]
        a = a.strip()
        if not a.startswith("0x0000000"):
            continue
        new_entry = TraceEntry(a)
        final.append(new_entry)

    with open("trace.example.processed", "w") as f:
        for entry in final:
            f.write(str(entry) + "\n")
    
    return final



def find_repeated_seq_with_length(lst, length):
    """
    In lst, find consecutively repeated sequence of length 'length', and condense them into one single occurence.
    """

    res = [] # (rep_start_idx, rep_count, rep_size)

    if len(lst) <= length:
        return res # dont bother

    curr_repeat_start = -1
    curr_repeat_count = 1

    i = length
    while i + length <= len(lst):
        # curr_ele = lst[i]
        if lst[i:i+length] == lst[i-length:i]:
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
                res.append((curr_repeat_start, curr_repeat_count, length))
                # reset the repeat session
                curr_repeat_start = -1
                curr_repeat_count = 1
                # if prev window is in a repeat session, we should not even look at it again later
                i += length
            else:
                # advance by one
                i += 1
    
    return res


def condense_trace(trace: List[TraceEntry], rep_info):
    res = []
    trace_idx_processed = 0
    for rep_start, rep_count, rep_size in rep_info:
        # add the prefix
        res += trace[trace_idx_processed: rep_start]
        # condense repeated sequence in the middle
        condensed = []
        for i in range(rep_size):
            # create a new trace entry
            old_addr = trace[rep_start+i].addr
            old_labels = trace[rep_start+i].labels
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


def main():
    trace = read_trace("trace.example")

    print(f"original len of trace: {len(trace)}")

    # rep_info = find_repeated_seq_with_length(trace, 1)
    # print(rep_info)

    # updated_trace = condense_trace(trace, rep_info)
    # print(f"updated len of trace: {len(updated_trace)}")

    max_condense_len = 10
    updated_trace = trace
    for i in range(1, max_condense_len+1):
        rep_info = find_repeated_seq_with_length(updated_trace, i)
        print(f"Size of rep_info for condense length {i}： {len(rep_info)}")
        updated_trace = condense_trace(updated_trace, rep_info)

    print(f"Len of updated trace (after {max_condense_len} condensations): {len(updated_trace)}")

    with open("trace.example.processed.condensed", "w") as f:
        for entry in updated_trace:
            f.write(str(entry) + "\n")

    ##################### Testing to make sure condensation generate seq of correct len #####################
    prev = ""
    new_length =0
    for f in trace:
        if f != prev:
            new_length += 1
        prev = f
            
    print(f"new length: {new_length}")

    another_length = len(trace)
    for rep_start, rep_count, rep_size in rep_info:
        another_length -= rep_count * rep_size - rep_size
    print(f"another length: {another_length}")

    ##################### Testing END #####################



    # for idx, f in enumerate(trace):
    #     if f == prev:
    #         if f not in single_repeat:
    #             single_repeat[f] = 2
    #         else:
    #             single_repeat[f] += 1
    #     prev = f

    # print(single_repeat)
    # reduced_len = len(trace)
    # for repeat in single_repeat.values():
    #     reduced_len -= repeat - 1

    # print("reduced len {}".format(reduced_len))

if __name__ == "__main__":
    main()
