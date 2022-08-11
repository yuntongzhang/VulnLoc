import pickle
import string
import multiprocessing
import numpy as np

# system setup
ProcessNum = np.min((10, multiprocessing.cpu_count()))

# Used for generating the random filename
FileNameChars = list(string.ascii_letters + string.digits)
FileNameLen = 30

# Process the binary file
def read_bin(path):
    with open(path, 'rb') as f:
        temp = f.readlines()
    content = b''.join(temp)
    return list(content)


def write_bin(path, inputs):
    with open(path, 'wb') as f:
        f.write(bytearray(list(inputs)))


# Process the normal text file
def read_txt(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.readlines()
    return content


def write_txt(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(content)


# Process the pickle file
def write_pkl(path, info):
    with open(path, 'wb') as f:
        pickle.dump(info, f)


def read_pkl(path):
    with open(path, 'rb') as f:
        info = pickle.load(f)
    return info


# Generating the temp filename
def gen_temp_filename():
    return ''.join(np.random.choice(FileNameChars, FileNameLen))
