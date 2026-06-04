import re
f = '/mnt/d/计算机资料/毕设/tygr_original/src/utils/learn.py'
s = open(f, encoding='utf-8').read()
s = re.sub(r'tPositive/\(tPositive \+ fNegative\)(?! if)',
           'tPositive/(tPositive + fNegative) if (tPositive + fNegative) > 0 else 0.0', s)
s = re.sub(r'tPositive/\(tPositive \+ fPositive\)(?! if)',
           'tPositive/(tPositive + fPositive) if (tPositive + fPositive) > 0 else 0.0', s)
s = re.sub(r'accurate_count/total_count(?!\s+if)',
           '(accurate_count/total_count if total_count else 0.0)', s)
s = re.sub(r'total_loss / num_processed(?!\s+if)',
           '(total_loss / num_processed if num_processed else 0.0)', s)
open(f, 'w', encoding='utf-8').write(s)
print('patched learn.py: guarded all metric divisions')
