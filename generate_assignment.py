#!/bin/python3

import struct

p = 115792089237316195423570985008687907852837564279074904382605163141518161494337

fileName = "foo.assn"
version = 1
n_commits = 1
n_gates = 2
header = [version, n_commits, n_gates]
al = [17, 19]
ar = [81735592402811432063697165888485582013767692432288167799485997511659878701885, 42660243403221756208684047108463966051045418418606543719907165367927743708440]
ao = [1, 1]
v = [117]

assert(len(al) == n_gates)
assert(len(ar) == n_gates)
assert(len(ao) == n_gates)
for i in range(n_gates):
    assert(al[i]*ar[i] % p == ao[i])
assert(len(v) == n_commits)

with open(fileName, 'wb') as f:
    f.write(struct.pack('i', version))
    f.write(struct.pack('i', n_commits))
    f.write(struct.pack('Q', n_gates))
    for x in al + ar + ao + v:
        f.write(b'\x20')
        f.write(x.to_bytes(32, byteorder='little'))
