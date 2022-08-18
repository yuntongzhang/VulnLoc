import os
import logging

import values


logger = None # should call init first
log_format = "[%(asctime)s-%(funcName)s-%(levelname)s]: %(message)s"
log_date_format = "%d-%b-%y %H:%M:%S"


def I(msg):
    """
    Info entry.
    """
    logger.info(msg)


def D(msg):
    """
    Debug entry.
    """
    logger.debug(msg)


def init_fuzz_log(config_info):
    global logger
    fuzz_logger = logging.getLogger('Fuzz')
    fuzz_logger.setLevel(logging.DEBUG)

    console_handler = create_console_handler()
    file_handler = logging.FileHandler(os.path.join(values.OutFolder, 'fuzz.log'))
    if values.Verbose:
        file_handler.setLevel(logging.DEBUG)
    else:
        file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(create_standard_formatter())

    fuzz_logger.addHandler(console_handler)
    fuzz_logger.addHandler(file_handler)
    logger = fuzz_logger

    logger.info(f'Output Folder: {values.OutFolder}')
    logger.debug(f"CVE: {values.Tag}")
    config_str = '\n'.join([f"\t{key} : {val}" for key, val in config_info.items()])
    logger.debug(f"Config Info: \n{config_str}")


def init_patchloc_log():
    global logger
    loc_logger = logging.getLogger('PatchLoc')
    loc_logger.setLevel(logging.DEBUG)

    console_handler = create_console_handler()
    file_handler = logging.FileHandler(os.path.join(values.OutFolder, 'patchloc.log'))
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(create_standard_formatter())

    loc_logger.addHandler(console_handler)
    loc_logger.addHandler(file_handler)
    logger = loc_logger

    logger.info(f"Output Folder: {values.OutFolder}")


def create_console_handler():
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_fmt = create_standard_formatter()
    console.setFormatter(console_fmt)
    return console


def create_standard_formatter():
    return logging.Formatter(fmt=log_format, datefmt=log_date_format)
