import pstats
import os
import re

fn_re = re.compile(r'perfd(?P<trial>\d+)(.+[/\\])+(?P<name>.*)_(?P<assets>\d+)_d(?P<depth>\d+)\.pstats')
out_dict = dict()
prepend_paths = map(lambda a: os.path.join('perfd%i' % a, 'd'), range(6))
#prepend_paths = map(lambda a: 'perf%i' % a, range(6))
for parent_path in prepend_paths:
    print '---- TRIAL %s ----' % parent_path
    for filename in os.listdir(parent_path):
        filename = os.path.join(parent_path, filename)
        p = pstats.Stats(filename)
        m = fn_re.match(filename)
        depth = m.group('depth')
        num_assets = m.group('assets') # unused
        scenario_name = m.group('name')
        trial = m.group('trial')
        time = p.strip_dirs().stats[(
            'ag_generator.py', 1158, 'main'
        )][3] # cumulative time in main function
        
        print 'Name %s-%s, assets %s, depth %s: time %0.2f' % (scenario_name, 
                                                            trial, num_assets, 
                                                            depth, time)
        
        depth = int(depth)
        trial = int(trial)
        out_dict.setdefault(depth, dict())
        out_dict[depth].setdefault(scenario_name, dict())
        out_dict[depth][scenario_name][trial] = time

print out_dict

lines = []
heading = []
for depth in sorted(out_dict.keys()):
    if not heading:
        new_heading = ['depth']
    new_line = [str(depth)]
    for scenario in out_dict[depth]:
        for trial in sorted(out_dict[depth][scenario].keys()):
            time = out_dict[depth][scenario][trial]
            new_line.append(str(time))
            if not heading:
                new_heading.append('%s (%i)' % (scenario, trial))
    if not heading:
        heading = ','.join(new_heading)
        lines.append(heading)
    new_line_str = ','.join(new_line)
    lines.append(new_line_str)
print '\n'.join(lines)