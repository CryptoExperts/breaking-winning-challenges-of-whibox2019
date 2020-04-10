# -*- coding: utf-8 -*-
import os
import sys
import logging
import numpy as np
from tqdm import tqdm, trange

np_formatter = {'float_kind': lambda x: '{:6.3f}'.format(
    x), 'int': lambda x: '0x{:0>2x}'.format(x)}
byte_formatter = {'int': lambda x: '{:02x}'.format(x)}
two_byte_formatter = {'int': lambda x: '{:04x}'.format(x)}
int_formatter = {'int': lambda x: '{:4d}'.format(x)}

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
log = logging.getLogger(__name__)


aes_sbox_inv = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
key_space = range(256)


def target_function(value, bit, key_guess):
    return (aes_sbox_inv[value ^ key_guess] >> bit) & 1


def target_group(pt, ct, byte):
    return ct[byte]


def load_trace(tracefile, byte):
    # read meta info
    log.info("Reading traces ....")
    with open(tracefile, 'rb') as f:
        # process meta-data
        n_traces, n_samples, sample_size = f.readline().strip().split(b' ')
        n_traces = int(n_traces)
        n_samples = int(n_samples)
        sample_size = int(sample_size)

    # initialize trace batches
    batch_traces = {
        i: [
            0.0,
            np.zeros(n_samples, dtype=np.int),
            np.zeros(n_samples, dtype=np.int)
        ]
        for i in key_space
    }

    # read traces
    with open(tracefile, 'rb') as f:
        f.readline()

        ones = np.ones(n_samples, dtype=np.int)
        for i in trange(n_traces):
            pt = f.read(16)
            ct = f.read(16)
            bits = f.read(n_samples)
            trace = np.frombuffer(bits, np.uint8)

            group = target_group(pt, ct, byte)
            pair = batch_traces[group]
            pair[0] += 1
            pair[1] += trace
            pair[2] += trace ^ ones

    return batch_traces, n_traces, n_samples


def _make_guess(mat, n_samples, byte, bit):
    max_peaks = mat.max(axis=1)
    max_peaks_idx = mat.argmax(axis=1)
    max_top = max_peaks.argsort()[::-1][:10]
    max_top_val = max_peaks[max_top]
    max_top_idx = max_peaks_idx[max_top]  # *1.0/self.n_samples

    log.info("""top %d max peaks byte %i, bit %i --
\tkey guess:    %s
\tposition:     %s
\trelative pos: %s
\tvalues:       %s
\tadvantage:    %02.1f %%""",
             len(key_space), byte, bit,
             np.array2string(max_top, formatter=byte_formatter,
                             max_line_width=np.inf),
             np.array2string(max_top_idx, formatter=int_formatter,
                             max_line_width=np.inf),
             np.array2string(max_top_idx*1.0/n_samples,
                             formatter=np_formatter,
                             max_line_width=np.inf),
             np.array2string(max_top_val, formatter=np_formatter,
                             max_line_width=np.inf),
             (max_top_val[0]/max_top_val[1]-1)*100)


def attack(batch_traces, n_traces, n_samples, target_byte, target_bit):
    mat = list()
    for guess in tqdm(key_space, desc="Loop over key guesses"):
        sum_ = np.zeros(n_samples, dtype=np.int)
        for batch in batch_traces:
            target_val = target_function(batch, target_bit, guess)
            if target_val == 0:
                sum_ += batch_traces[batch][1]
            else:
                sum_ += batch_traces[batch][2]

        mat.append(1-2.0*sum_/n_traces)
    mat = np.abs(np.array(mat))
    _make_guess(mat, n_samples, target_byte, target_bit)


if __name__ == '__main__':
    _, tracefile, target_byte = sys.argv
    target_byte = int(target_byte)

    batch_traces, n_traces, n_samples = load_trace(tracefile, target_byte)
    for target_bit in range(8):
        log.info("Attack byte {:02d}, bit {:02d}".format(target_byte,
                                                         target_bit))
        attack(batch_traces, n_traces, n_samples, target_byte, target_bit)
