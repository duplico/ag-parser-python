import sys
import ag_parser
import itertools
import operator
import networkx as nx

# Network state:
# ((asset frozenset of strings), (fact frozenset of tuples))
# Fact tuple: ('quality', asset, name, value)
# Fact tuple: ('topology', asset1, asset2, name[, value])

# TODO: There would probably be some performance benefits to making these
# immutable:
class NetworkModel(object):
    class Asset(object):
        def __init__(self, name):
            self.name = name
            self.qualities = {}
            self.topologies = {}
            self.factset = set()
        
        def get_quality(self, name):
            if name in self.qualities:
                return self.qualities[name]
            else:
                return False
        
        def set_quality(self, name, value):
            if name in self.qualities and self.qualities[name] == value:
                return False # No change
            elif name in self.qualities:
                # Remove the old fact that this one is clobbering.
                self.factset.remove(('quality', self.name, name,
                                     self.qualities[name]))
            self.factset.add(('quality', self.name, name, value))
            self.qualities[name] = value
            return True # Changed
        
        def del_quality(self, name):
            if name in self.qualities:
                # Remove the fact that this one is deleting:
                self.factset.remove(('quality', self.name, name,
                                     self.qualities[name]))
                del self.qualitied[name]
                return True # Changed.
            else:
                # No fact to delete
                return False # Not changed.
        
        def get_topology(self, dest, name):
            if dest in self.topologies and name in self.topologies[dest]:
                return self.topologies[name][dest]
            else:
                return False
        
        # We're using topologies[DESTINATION_ASSET] = {SET OF TOPOLOGIES} here.
        def set_topology(self, dest, name):
            if dest in self.topologies and name in self.topologies[dest] and \
                    self.topologies[dest][name]:
                # No change
                return False
            elif dest in self.topologies and name in self.topologies[dest]:
                # Topology "exists" but is wrong
                self.topologies[dest][name] = True
                # TODO for hybrid we need a remove here.
                return True
            else:
                # Topology entry does not exist
                self.factset.add(('topology',self.name,dest,name))
                self.topologies[dest] = {name : True,}
                return True
        
        def del_topology(self, dest, name):
            if dest in self.topologies and name in self.topologies[dest] and \
                    self.topologies[dest][name]:
                del self.topologies[dest][name]
                self.factset.remove(('topology',self.name,dest,name))
                return True
            else:
                # No change
                return False
        
        def get_facts(self):
            """
            Returns the facts about (from) this asset in a nonfrozen set.
            """
            return self.factset
    
    existing_states = {}
    
    def get_existing(netstate):
        if netstate in existing_states:
            return existing_states[netstate]
        else:
            return False
    
    def __init__(self, netstate):
        NetworkModel.existing_states[netstate] = self
        self.netstate = netstate # Takes the canonical, hashable format
        self.assets = {} # Dictionary of Asset objects, for convenience.
        self.needs_regen = False
        for asset in netstate[0]:
            self.assets[asset] = NetworkModel.Asset(asset)
        for fact in netstate[1]:
            if fact[0] == 'quality':
                self.update_regen(self.assets[fact[1]].set_quality(fact[2],
                                                                   fact[3]))
            elif fact[0] == 'topology':
                self.update_regen(self.assets[fact[1]].set_topology(fact[2],
                                                                    fact[3]))
        self.needs_regen = False
    
    def update_regen(self, new_change):
        self.needs_regen = self.needs_regen or new_change
        return self.needs_regen
    
    def get_quality(self, asset, name):
        return self.assets[asset].get_quality(name)
    
    def get_topology(self, source, dest, name):
        return self.assets[source].get_topology(dest, name)
    
    def set_quality(self, asset, name, value):
        self.update_regen(self.assets[asset].set_quality(name, value))
    
    def set_topology(self, source, dest, name):
        self.update_regen(self.assets[source].set_topology(dest, name))
    
    def del_quality(self, asset, name):
        self.update_regen(self.assets[asset].del_quality(name))
    
    def del_topology(self, source, dest, name):
        self.update_regen(self.assets[source].del_topology(dest, name))
    
    def to_netstate(self):
        if not self.needs_regen:
            return self.netstate
        else:
            self.needs_regen = False
            factsets = [asset.get_facts() for asset in self.assets.values()]
            facts = frozenset(set.union(*factsets))
            assets = frozenset([asset for asset in self.assets])
            self.netstate = (assets, facts)
            return self.netstate
    
    def validate_attack(self, attack, exploit_dict):
        # attack takes the form (exploit_name (binding_tuple))
        # Fact tuple: ('quality', asset, name, value)
        # Fact tuple: ('topology', asset1, asset2, name[, value])
        exploit = exploit_dict[attack[0]]
        binding_dict = {}
        for i in range(len(exploit.params)):
            binding_dict[exploit.params[i]] = attack[1][i]
        # These conditions are all WAY too simplistic for the hybrid extensions:
        for precondition in exploit.preconditions:
            if precondition.type == 'quality':
                fact = ('quality', binding_dict[precondition.asset],
                        precondition.name, precondition.value)
                if fact not in self.to_netstate()[1]:
                    return False
            elif precondition.type == 'topology':
                fact = ('topology', binding_dict[precondition.source],
                        binding_dict[precondition.dest], precondition.name)
                if fact not in self.to_netstate()[1]:
                    return False
                if precondition.direction == '<->': # Test opposite direction?
                    fact = ('topology', binding_dict[precondition.source],
                            binding_dict[precondition.dest], precondition.name)
                    if fact not in self.to_netstate()[1]:
                        return False
            else:
                return False
        return True

# TODO: replace the param tuple with a dictionary?
def get_attack_bindings(network_model, exploit_dict):
    """
    Return format is (exploit name, (param tuple))
    """
    assets = network_model.assets
    attacks = []
    
    # For every exploit:
    for exploit_name in exploit_dict:
        exploit = exploit_dict[exploit_name]
        
        # Generate a list of permutations of network assets the length
        # of the exploit's parameter list (possible asset parameter bindings):
        param_bindings = list(itertools.permutations(list(assets),
                                                     len(exploit.params)))
        
        # Append the exploit name with these bindings to the list of attacks:
        attacks += map(lambda a: (exploit_name, a), param_bindings)
    return attacks

def get_successor_state(network_state, attack, exploit_dict):
    successor_assets = network_state[0]
    network_model = NetworkModel(network_state)
    for postcondition in exploit_dict[attack[0]].postconditions:
        print postcondition
        if postcondition.operation == 'insert':
            pass
        elif postcondition.operation == 'delete':
            if postcondition.type == 'topology':
                pass
            elif postcondition.type == 'quality':
                pass

def get_attacks(network_model, exploit_dict, attack_bindings):
    return [attack for attack in attack_bindings \
            if network_model.validate_attack(attack, exploit_dict)]

def generate_attack_graph(analysis_states, depth, exploit_dict, attack_bindings,
                          attack_graph=None):
    if not attack_graph:
        attack_graph = nx.Graph()
    if len(analysis_states) == 0 or depth == 0:
        return attack_graph
    successor_states = []
    # For each state to be processed for successors
    for analysis_state in analysis_states:
        analysis_model = NetworkModel(analysis_state)
        if analysis_state not in attack_graph:
            attack_graph.add_node(analysis_state)
        # For each valid attack in that state
        for attack in get_attacks(analysis_model, exploit_dict,
                                  attack_bindings):
            successor_state = get_successor_state(analysis_state, attack,
                                                  exploit_dict)
            # if successor_state in attack_graph:
                # pass
            # else:
                # successor_states += [successor_state]
    return generate_attack_graph(successor_states, depth-1, exploit_dict,
                                 attack_bindings, attack_graph)

# TODO: This is currently totally discrete:
def nsfactlist_from_nm(netmodel):
    factlist = []
    for netmodel_fact in netmodel.facts:
        if netmodel_fact.type == 'quality':
            factlist.append((netmodel_fact.type, netmodel_fact.asset,
                         netmodel_fact.name, netmodel_fact.value))
        elif netmodel_fact.type == 'topology':
            factlist.append((netmodel_fact.type, netmodel_fact.source,
                         netmodel_fact.dest, netmodel_fact.name))
            if netmodel_fact.direction == '<->':
                factlist.append((netmodel_fact.type, netmodel_fact.dest,
                                 netmodel_fact.source, netmodel_fact.name))
    return factlist

def ns_from_nm(netmodel):
    assets = frozenset(netmodel.assets)
    facts = frozenset(nsfactlist_from_nm(netmodel))
    return (assets, facts)

def main(nm_file, xp_file):
    netmodel = ag_parser.networkmodel.parseFile(nm_file)
    exploits = ag_parser.exploits.parseFile(xp_file)
    exploit_dict = {}
    for exploit in exploits:
        exploit_dict[exploit.name] = exploit
    initial_network_state = ns_from_nm(netmodel)
    generate_attack_graph([initial_network_state,], 5, exploit_dict,
        get_attack_bindings(netmodel, exploit_dict))

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'usage: python ag_generator.py nmfile xpfile'
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])