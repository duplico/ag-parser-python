import sys
import ag_parser
import itertools

exploit_dict = {}

# Network state:
# ((asset tuple), (fact tuple))
# Fact tuple: (quality, asset, name, value)
# Fact tuple: (topology, asset1, asset2, name[, value])

#class network_state(object):
#    def __init__(self, ):
        

def get_attack_bindings(network_model):
    """
    Return format is (exploit name, (param tuple))
    """
    assets = network_model.assets
    attacks = []
    for exploit_name in exploit_dict:
        exploit = exploit_dict[exploit_name]
        param_bindings = list(itertools.permutations((list(assets)), len(exploit.params)))
        attacks += map(lambda a: (exploit_name, a), param_bindings)
    print attacks

def get_successor_state(network_state, attack):
    pass

def get_attacks(network_state):
    pass

def generate_attack_graph(analysis_states, depth):
    if len(analysis_states) == 0 or depth == 0:
        return # Ideally we should return something here.
    successor_states = []
    # For each state to be processed for successors
    for analysis_state in analysis_states:
        # For each valid attack in that state
        for attack in get_attacks(analysis_state):            
            successor_state = get_successor_state(analysis_state, attack)
            # if successor_state in attack_graph:
                # pass
            # else:
                # successor_states += [successor_state]
    generate_attack_graph(next_states, depth-1)

def main(nm_file, xp_file):
    netmodel = ag_parser.networkmodel.parseFile(nm_file)
    exploits = ag_parser.exploits.parseFile(xp_file)
    global exploit_dict
    for exploit in exploits:
        exploit_dict[exploit.name] = exploit

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'usage: python ag_generator.py nmfile xpfile'
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])