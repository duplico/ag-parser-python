import cProfile
import os
import sys

from ag_generator import main

def profile_assets():
    global nm_file, xp_file, depth # make exec work
    fb_dict = dict(trials=range(1,6), depth=10) # (1,6)
    td_dict = dict(trials=range(1,5), depth=10000) # (1,5)
    if not os.path.exists('perf/a'):
        os.makedirs('perf/a')
    for scenario, details in dict(fullbunny=fb_dict, thesis_dash7=td_dict).items():
        xp_file = 'examples/%s.xp' % scenario
        depth = details['depth']
        for trial in details['trials']:
            nm_file = 'examples/%s_%i.nm' % (scenario, trial)
            cProfile.run('main(nm_file, xp_file, depth, state_graph=True, viz_graph=False, viz_states=False)',
                         'perf/a/%s_%i_d%i.pstats' % (scenario, trial, depth))

def profile_depths():
    global nm_file, xp_file, depth # Make exec work
    fb_dict = dict(trial=3, depths=range(2,23,4)) # (1,6)
    td_dict = dict(trial=3, depths=range(2,23,4)) # (1,5)
    if not os.path.exists('perf/d'):
        os.makedirs('perf/d')
    for scenario, details in dict(fullbunny=fb_dict, thesis_dash7=td_dict).items():
        xp_file = 'examples/%s.xp' % scenario
        trial = details['trial']
        for depth in details['depths']:
            nm_file = 'examples/%s_%i.nm' % (scenario, trial)
            cProfile.run('main(nm_file, xp_file, depth, state_graph=True, viz_graph=False, viz_states=False)',
                         'perf/d/%s_%i_d%i.pstats' % (scenario, trial, depth))

def script_main(assets=True, depths=True):
    if assets:
        profile_assets()
    if depths:
        profile_depths()

if __name__ == '__main__':
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print 'Usage: profile_suite.py [-a] [-d] [-h|--help]'
        print '   -a: Profile assets'
        print '   -d: Profile depths'
        print '   -h: Print this message.'
        sys.exit()
    do_profile_assets = '-a' in sys.argv
    do_profile_depths = '-d' in sys.argv
    script_main(do_profile_assets, do_profile_depths)