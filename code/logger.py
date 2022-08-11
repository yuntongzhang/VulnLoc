import os
import logging

import values


def init_log(tag, verbose, config_info):
    folder = config_info['folder']
    values.OutFolder = os.path.join(folder, 'fuzzer')  # (YN: adapted ouput folder)
    if os.path.exists(values.OutFolder):
        raise Exception(f"ERROR: Output folder already exists! -> {values.OutFolder}")

    os.mkdir(values.OutFolder)

    # (YN: added folders for generated inputs)
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

    log_path = os.path.join(values.OutFolder, 'fuzz.log')
    if verbose == 'True':
        logging.basicConfig(filename=log_path, filemode='a+', level=logging.DEBUG,
                            format="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s",
                            datefmt="%d-%b-%y %H:%M:%S")

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        fmt="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s", datefmt="%d-%b-%y %H:%M:%S")
    console.setFormatter(console_fmt)
    logging.getLogger().addHandler(console)
    logging.info(f'Output Folder: {values.OutFolder}')
    logging.debug(f"CVE: {tag}")
    config_str = '\n'.join([f"\t{key} : {val}" for key, val in config_info.items()])
    logging.debug(f"Config Info: \n{config_str}")
