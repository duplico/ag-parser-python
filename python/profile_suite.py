from ag_generator import main
import cProfile

fb_dict = dict(trials=range(1,6), depth=10) # (1,6)
td_dict = dict(trials=range(1,5), depth=10000) # (1,5)
for scenario, details in dict(fullbunny=fb_dict, thesis_dash7=td_dict).items():
    xp_file = 'examples/%s.xp' % scenario
    depth = details['depth']
    for trial in details['trials']:
        nm_file = 'examples/%s_%i.nm' % (scenario, trial)
        cProfile.run('main(nm_file, xp_file, depth, state_graph=True, viz_graph=False, viz_states=False)',
                     'perf/%s_%i.pstats' % (scenario, trial))