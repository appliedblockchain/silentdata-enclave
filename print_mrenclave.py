import sys

with open(sys.argv[1], 'r') as f:
    found_mrenclave = False
    mrenclave = ''
    for line in f:
        if line.find('metadata->enclave_css.body.enclave_hash.m') == 0:
            found_mrenclave = True
            continue
        if found_mrenclave:
            if line.find('metadata') == 0:
                break
            mr_hexes = line.split(' ')
            for mr_hex in mr_hexes:
                mrenclave += mr_hex[2:]
print('MRENCLAVE = ' + str(mrenclave))
with open("MRENCLAVE_value.txt", "w") as f:
    f.write(str(mrenclave))
