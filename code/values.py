import os

deps_dir = "/opt/fuzzer/deps"
e9patch_dir = os.path.join(deps_dir, "e9patch")
redfat_dir = os.path.join(deps_dir, "RedFat")

dynamorio_path = os.path.join(deps_dir, "dynamorio/build/bin64/drrun")
iftracer_path = os.path.join(deps_dir, "iftracer/iftracer/libiftracer.so")
# iflinetracer_path="/opt/fuzzer/deps/iftracer/ifLineTracer/libifLineTracer.so"
# libcbr_path="/opt/fuzzer/deps/dynamorio/build/api/bin/libcbr.so"

DefaultItems = ['trace_cmd', 'crash_cmd', 'poc', 'poc_fmt',
                'folder', 'mutate_range', 'crash_tag', 'bin_path']
OutFolder = ''
TmpFolder = ''
TraceFolder = ''
ConcentratedInputFolder = ''  # (YN: added folder for concentrated generated inputs)
AllInputFolder = ''  # (YN: added folder for all generated inputs)

PocTracePath = ''
SavedReportPath = ''
SavedSeedsPath = ''
SavedSeedHashesPath = ''
VarRankingPath = ''

# Each element is in the fmt of [<process_tag>, <seed_content>].
#   <process_tag>: True (selected) / False (not selected)
SeedPool = []
SeedTraceHashList = []
# Each element if in the fmt of [<trace_hash>, <tag>]. <tag>: m - malicious / b - benign
ReportCollection = []
TraceHashCollection = []
GlobalTimeout = 0
LocalTimeout = 0
DefaultRandSeed = 3
DefaultMutateNum = 200
DefaultMaxCombination = 2
MaxCombineNum = 10**20
ConcentratedInputCounter = 0  # (YN: added input counter)
inputFormat = 'bfile'  # or 'text' (YN: added to determine input format)
AllInputCounter = 0  # (YN: added input counter)
StoreAllInputs = False  # (YN: added flag for generating all inputs)

ProcessNum = 1  # how many processes to use for fuzzing and rank calc?
ShowNum = 1  # how many instructions to show during patch loc ranking?
PatchLocFunc = 'calc'  # what to do during patch loc?

Tag = ''  # tag of the CVE being processed
Verbose = True
