#!/bin/python3

import struct

fileName = "foo.assn"
version = 1
n_commits = 1
n_gates = 2
header = [version, n_commits, n_gates]
al = [17, 19]
ar = [17, 17]
ao = [1, 1]
v = [117]

assert(len(al) == n_gates)
assert(len(ar) == n_gates)
assert(len(ao) == n_gates)
assert(len(v) == n_commits)

with open(fileName, 'wb') as f:
    f.write(struct.pack('i', version))
    f.write(struct.pack('i', n_commits))
    f.write(struct.pack('Q', n_gates))
    for x in al + ar + ao + v:
        f.write(x.to_bytes(256, byteorder='little'))
