#!/usr/bin/env python3
import sys

path = sys.argv[1]
Q3 = chr(39) * 3

with open(path) as f:
    lines = f.readlines()

result = []
for line in lines:
    s = line.rstrip('\n')
    if s.strip() == 'print ' + Q3:
        result.append(line.replace('print ' + Q3, 'print(' + Q3))
    elif s.strip() == Q3:
        result.append(Q3 + ')\n')
    elif 'except Exception, e:' in line:
        result.append(line.replace('except Exception, e:', 'except Exception as e:'))
    else:
        result.append(line)

with open(path, 'w') as f:
    f.writelines(result)

print('[+] Fixed DrvGen.py')
