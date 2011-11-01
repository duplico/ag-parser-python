#>out = !ls
import pstats
out_string = ''
for filename in out:
    p = pstats.Stats(filename)
    print filename, p.strip_dirs().stats[(
        'ag_generator.py', 1158, 'main'
    )][3] # cumulative time in main function