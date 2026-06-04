#!/usr/bin/env python3
"""Generate a diverse C corpus for TYGR type-recovery training.

Each generated function declares several locals of varied types and *uses* them
(arithmetic, deref, array indexing, calls) so they materialize in the -g binary with
DWARF type labels. Goal: broad type-feature vocabulary + enough functions to train a
usable x64.O0 GlowGNN (fixing the undersized-embedding crash from the 36-func toy set).
"""
import os, random, sys

random.seed(1234)
OUT = sys.argv[1] if len(sys.argv) > 1 else '/mnt/d/计算机资料/毕设/data/corpus'
N_FILES = int(sys.argv[2]) if len(sys.argv) > 2 else 80
FUNCS_PER_FILE = 8
os.makedirs(OUT, exist_ok=True)

SCALARS = ['char', 'short', 'int', 'long', 'unsigned int', 'unsigned long',
           'unsigned char', 'float', 'double', 'long long']
PTRS = ['char *', 'int *', 'long *', 'short *', 'double *', 'unsigned char *', 'void *']
ARRS = [('char', 16), ('char', 64), ('int', 8), ('int', 32), ('long', 8), ('short', 16)]

HDR = '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n'


def gen_func(fid):
    lines = [f'long f{fid}(long a0, char *a1, int a2) {{']
    nlocals = random.randint(4, 8)
    used = []
    for i in range(nlocals):
        kind = random.choice(['scalar', 'scalar', 'ptr', 'arr'])
        if kind == 'scalar':
            t = random.choice(SCALARS)
            lines.append(f'  {t} v{i} = ({t})(a0 + {i});')
            used.append(('scalar', i, t))
        elif kind == 'ptr':
            t = random.choice(PTRS)
            lines.append(f'  {t}v{i} = ({t})a1;')
            used.append(('ptr', i, t))
        else:
            bt, n = random.choice(ARRS)
            lines.append(f'  {bt} v{i}[{n}];')
            used.append(('arr', i, (bt, n)))
    # use the locals so they aren't optimized away (compiled -O0 anyway)
    acc = 'long acc = a2;'
    lines.append('  ' + acc)
    for kind, i, t in used:
        if kind == 'scalar':
            lines.append(f'  acc += (long)v{i};')
        elif kind == 'ptr':
            lines.append(f'  if (v{i}) acc += (long)((char*)v{i})[0];')
        else:
            bt, n = t
            lines.append(f'  for (int k=0;k<{n};k++) v{i}[k] = (k+a2);')
            lines.append(f'  acc += v{i}[a2 % {n}];')
    lines.append('  return acc;')
    lines.append('}')
    return '\n'.join(lines)


count = 0
for fi in range(N_FILES):
    body = HDR
    for fj in range(FUNCS_PER_FILE):
        body += gen_func(count) + '\n\n'
        count += 1
    # a main that references every function so they are kept
    body += 'int main(int argc, char **argv){\n  long s=0;\n'
    base = fi * FUNCS_PER_FILE
    for fj in range(FUNCS_PER_FILE):
        body += f'  s += f{base+fj}(argc, argv[0], argc);\n'
    body += '  printf("%ld\\n", s);\n  return 0;\n}\n'
    open(os.path.join(OUT, f'c{fi:03d}.c'), 'w').write(body)

print(f'generated {N_FILES} files, {count} functions in {OUT}')
