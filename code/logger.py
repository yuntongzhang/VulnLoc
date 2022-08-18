import os
import logging

import values


def init_fuzz_log(config_info):
    log_path = os.path.join(values.OutFolder, 'fuzz.log')
    if values.Verbose:
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
    logging.debug(f"CVE: {values.Tag}")
    config_str = '\n'.join([f"\t{key} : {val}" for key, val in config_info.items()])
    logging.debug(f"Config Info: \n{config_str}")


def init_patchloc_log():
    log_path = os.path.join(values.OutFolder, 'patchloc.log')
    logging.basicConfig(filename=log_path, filemode='a+', level=logging.DEBUG,
                        format="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s",
                        datefmt="%d-%b-%y %H:%M:%S")
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter(fmt="[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s",
                                    datefmt="%d-%b-%y %H:%M:%S")
    console.setFormatter(console_fmt)
    logging.getLogger().addHandler(console)
    logging.info(f"Output Folder: {values.OutFolder}")
