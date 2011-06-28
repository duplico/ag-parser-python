"""
Module providing token-valued attack graph generation functionality.

This is the Python version of the tool to generate University of Tulsa style
attack graphs from formal specifications of assets, topologies, qualities, and
exploit patterns.

(c) 2011, Institute for Information Security at The University of Tulsa

Author: George R Louthan IV
"""

import sys
import os
import ag_parser
import itertools
import operator
import networkx as nx
#import matplotlib.pyplot as plt

DEBUG = True

# TODO: There would probably be some performance benefits to making these
# immutable:
class NetworkModel(object):
    """
    A NetworkModel specifies a single network state with convenience functions.
    
    A network model can be thought of as the mutable version of a network
    state; it encapsulates a network state and provides accessor and modifier
    functions permitting easy interaction with the network model.
    
    A network state, on the other hand, is a two-tuple: the first element is
    a frozenset containing the string names of all the assets in the state;
    the second element is a frozenset containing "fact tuples". Fact tuples
    take the following format:
    
    Network state: ((asset frozenset of strings), (frozenset of fact tuples))
    For qualities: ('quality', asset, name, value)
    For topologies: ('topology', asset1, asset2, name)
    For platforms: ('platform', asset, name, tuple(name.split(':')))
    
    The mutability of a NetworkModel is not guaranteed for perpetuity; its
    functionality MAY change for performance reasons.
    """

    class Asset(object):
        """
        Convenience class representing a single asset and all its properties.
        """
        def __init__(self, name):
            self.name = name
            self.qualities = {}
            self.topologies = {}
            self.factset = set()
            self.platforms = set() # This is a set of :-split CPEs
        
        def get_quality(self, name):
            """
            Returns the a named quality fact or False if it doesn't exist.
            """
            if name in self.qualities:
                return self.qualities[name]
            else:
                return False
        
        def set_quality(self, name, value):
            """
            Sets the value of the named quality.
            
            Returns True if this operation will require an update to the fact
            base, False if it will not.
            """
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
            """
            Deletes a named quality from this asset.
            
            Returns True if this operation will require an update to the fact
            base, False if it will not.
            """
            if name in self.qualities:
                # Remove the fact that this one is deleting:
                self.factset.remove(('quality', self.name, name,
                                     self.qualities[name]))
                del self.qualities[name]
                return True # Changed.
            else:
                # No fact to delete
                return False # Not changed.
        
        def set_platform(self, platform):
            # TODO: match better
            # TODO: conflict detection
            candidate = self.has_platform(platform)
            if candidate:
                return False # No change
            else:
                self.factset.add(('platform', self.name, ':'.join(platform),
                                 platform))
                self.platforms.add(platform)
                return False
        
        def del_platform(self, platform):
            candidate = self.has_platform(platform)
            if candidate:
                self.platforms.remove(candidate)
                self.factset.remove(('platform', self.name, ':'.join(candidate),
                                     candidate.split))
                return True
            else:
                return False
        
        def has_platform(self, platform):
            # Platform is a tuple
            for cpe in self.platforms:
                if len(cpe) >= len(platform):
                    ret = False
                    for components in zip(cpe, platform):
                        if components[0] == components[1] or platform == '':
                            ret = True
                        else:
                            ret = False
                            break
                        if ret:
                            return cpe # Return the matched platform
            return False
        
        def get_topology(self, dest, name):
            """
            Query the existence of a named topology and destination.
            
            Returns the topology fact if it exists, and False otherwise.
            """
            if dest in self.topologies and name in self.topologies[dest]:
                return self.topologies[name][dest]
            else:
                return False
        
        # We're using topologies[DESTINATION_ASSET] = {SET OF TOPOLOGIES} here.
        def set_topology(self, dest, name):
            """
            Sets a named topology to the named destination.
            
            Returns True if this operation will require an update to the fact
            base, False if it will not.
            """
            if dest in self.topologies and name in self.topologies[dest] and \
                    self.topologies[dest][name]:
                # No change
                return False
            elif dest in self.topologies and name in self.topologies[dest]:
                # Topology "exists" but is wrong
                self.topologies[dest][name] = True
                # TODO for hybrid we need a remove here.
                assert(False) # Should be unreachable.
                return True
            else:
                # Topology entry does not exist
                self.factset.add(('topology',self.name,dest,name))
                self.topologies[dest] = {name : True,}
                return True
        
        def del_topology(self, dest, name):
            """
            Deletes a named topology with a named destination asset.
            
            Returns True if this operation will require an update to the fact
            base, False if it will not.
            """
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
        
        def __str__(self):
            ret = self.name
            qstring = ''
            pstring = ''
            for fact in self.factset:
                if fact[0] == 'quality':
                    qstring += '\nq:%s=%s' % (fact[2], fact[3])
                elif fact[0] == 'platform':
                    pstring += '\ncpe:/%s' % fact[2] # TODO
            ret+=qstring
            ret+=pstring
            return ret
    
    def __init__(self, netstate):
        """
        Takes a network state tuple and constructs a network model from it.
        """
        
        self.netstate = netstate # Takes the canonical, hashable
                                 # tuple-of-frozensets format.
        self.assets = {} # Dictionary of Asset objects.
        self.needs_regen = False # Whether the factbase is out of date.
        
        for asset in netstate[0]: # Enumerate the assets in the network model:
            self.assets[asset] = NetworkModel.Asset(asset)
        
        for fact in netstate[1]: # Load all our facts into our asset objects:
            if fact[0] == 'quality':
                self.update_regen(self.assets[fact[1]].set_quality(fact[2],
                                                                   fact[3]))
            elif fact[0] == 'topology':
                self.update_regen(self.assets[fact[1]].set_topology(fact[2],
                                                                    fact[3]))
            elif fact[0] == 'platform':
                self.update_regen(self.assets[fact[1]].set_platform(fact[3]))
        
        self.needs_regen = False # As constructed, this object is up to date.
    
    def update_regen(self, new_change):
        """
        Marks the factbase for regeneration if it is ever passed True.
        """
        self.needs_regen = self.needs_regen or new_change
        return self.needs_regen
    
    def get_quality(self, asset, name):
        """
        Returns the fact for the named quality of the named asset.
        """
        return self.assets[asset].get_quality(name)
    
    def get_topology(self, source, dest, name):
        """
        Returns the fact for the named topology between the named assets.
        """
        return self.assets[source].get_topology(dest, name)
    
    def set_quality(self, asset, name, value):
        """
        Sets a named quality on a named asset to a given value.
        """
        self.update_regen(self.assets[asset].set_quality(name, value))
    
    def set_topology(self, source, dest, name):
        """
        Sets a named topology between specified assets.
        """
        self.update_regen(self.assets[source].set_topology(dest, name))
    
    def set_platform(self, asset, cpe_tuple):
        self.update_regen(self.assets[asset].set_platform(cpe_tuple))
    
    def del_quality(self, asset, name):
        """
        Deletes a quality on an asset.
        """
        self.update_regen(self.assets[asset].del_quality(name))
    
    def del_topology(self, source, dest, name):
        """
        Deletes a one-way topology.
        """
        self.update_regen(self.assets[source].del_topology(dest, name))
    
    def del_platform(self, asset, cpe_tuple):
        self.update_regen(self.assets[asset].del_platform(cpe_tuple))
    
    def to_netstate(self):
        """
        Returns the canonical tuple-of-frozensets network state representation.
        """
        # If we haven't updated anything since we last stored the network state,
        # we can just return our stored network state representation.
        if not self.needs_regen:
            return self.netstate
        else: # Otherwise, we are going to need to regenerate it.
            self.needs_regen = False
            # This comprehension results in a list of sets of facts from our
            # asset objects:
            factsets = [asset.get_facts() for asset in self.assets.values()]
            # Unwrap this list into arguments of set.union() in order to
            # combine them into a single set, which is then frozen.
            facts = frozenset(set.union(*factsets))
            # This comprehension results in a list of asset names as strings,
            # which we freeze into a frozenset:
            assets = frozenset([asset for asset in self.assets])
            # Wrap it up into a tuple and return it:
            self.netstate = (assets, facts)
            return self.netstate
    
    def validate_attack(self, attack, exploit_dict):
        """
        Determines whether a bound attack's preconditions match this netmodel.
        
        Parameters:
            attack - A tuple of the form (exploit name, {parameter name : asset})
            exploit_dict - A dictionary containing all the exploit names as
                           keys and their parsed form as values.
        Returns true if the attack's preconditions hold on this network model.
        """

        exploit = exploit_dict[attack[0]]
        binding_dict = attack[1]
        
        # These conditions are all WAY too simplistic for the hybrid extensions.
        # All we're doing here is checking generated fact tuples of the
        # preconditions for membership in the network model's fact base. TODO:
        # for the hybrid extensions we will need to do more rigorous testing
        # based on operators and actually querying and parsing the individual
        # facts in the factbase.
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
    
    def get_state_graph(self, label=False):
        state_graph = nx.MultiDiGraph()
        for asset in self.assets:
            node_label = str(self.assets[asset])
            if label:
                node_label = label + ':' + node_label
            state_graph.add_node(asset, label=node_label)
        for asset in self.assets:
            for fact in self.assets[asset].get_facts():
                if fact[0] == 'topology':
                    state_graph.add_edge(fact[1],fact[2],label=fact[3])
        return state_graph

def get_attack_bindings(network_model, exploit_dict):
    """
    Get every possible binding for every possible exploit.
    
    Return format is a list of elements of the form:
        (exploit name, {param : binding, ...}).
    This form is the canonical representation of an attack binding.
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
        attacks += map(lambda a: (exploit_name, dict(zip(exploit.params, a))),
                       param_bindings)
    return attacks

def get_pretty_attack(attack, exploit_dict):
    exploit = exploit_dict[attack[0]]
    params = []
    for formal_parameter in exploit.params:
        params.append(attack[1][formal_parameter])
    return '%s(%s)' % (attack[0], ','.join(params))

def get_successor_state(network_state, attack, exploit_dict):
    """
    Returns the successor state of applying an attack to a network state.
    """
    
    # Assets are currently always unchanged.
    successor_assets = network_state[0]
    
    # Build ourselves an intermediate, mutable copy of the predecessor state:
    network_model = NetworkModel(network_state)
    binding_dict = attack[1]
    
    # Successively apply each of the exploit's postconditions according to
    # our chosen binding:
    for postcondition in exploit_dict[attack[0]].postconditions:
        if postcondition.operation == 'insert':
            if postcondition.type == 'topology':
                network_model.set_topology(binding_dict[postcondition.source],
                                           binding_dict[postcondition.dest],
                                           postcondition.name)
            elif postcondition.type == 'quality':
                network_model.set_quality(binding_dict[postcondition.asset],
                                          postcondition.name,
                                          postcondition.value)
        elif postcondition.operation == 'delete':
            if postcondition.type == 'topology':
                network_model.del_topology(binding_dict[postcondition.source],
                                           binding_dict[postcondition.dest],
                                           postcondition.name)
            elif postcondition.type == 'quality':
                network_model.del_quality(binding_dict[postcondition.asset],
                                          postcondition.name)
        else:
            assert(False) # Should be unreachable.
    
    # Freeze the mutable network model object into a hashable, immutable
    # network state tuple-of-frozensets, which we then return:
    return network_model.to_netstate()

def get_attacks(network_model, exploit_dict, attack_bindings):
    """
    Returns all attacks that can be launched against the network in its state.
    """
    # This list comprehension simply copies the attacks out of attack_bindings
    # that happen to validate their preconditions according to the network
    # model object's validate_attack method.
    return [attack for attack in attack_bindings \
            if network_model.validate_attack(attack, exploit_dict)]

def generate_attack_graph(analysis_states, depth, exploit_dict, attack_bindings,
                          attack_graph=None, next_label=0):
    """
    Recursively generate an attack graph, to a given depth.
    
    Parameters:
        analysis_states -   Iterable of network state tuple-of-frozensets
                            representing the states to be explored.
        
        depth -             Maximum "depth" to explore to (that is, how many
                            iterations of the generation algorithm without
                            running out of new states we need before we give up.
        
        exploit_dict -      Dictionary of exploit names (keys) and raw parsed
                            representation of those exploits (values)
        
        attack_bindings -   Exhaustive list of (valid and invalid) ways to bind
                            assets to exploit pattern parameters, like what's
                            returned by the get_attack_bindings function.
        
        attack_graph -      A NetworkX MultiDiGraph representation of the
                            attack graph so far.
    """
    # Check to see if we need to initialize the attack graph:
    if not attack_graph:
        attack_graph = nx.MultiDiGraph()
    
    # Base case (time to stop):
    if len(analysis_states) == 0 or depth == 0:
        return attack_graph
    
    # This will hold the new (not existing) states that succeed the states
    # in analysis_states; on the next recursion these will be the new
    # analysis_states.
    successor_states = []

    # For each state to be processed for successors:
    for analysis_state in analysis_states:
        if DEBUG: print "Analysis state: %s" % str(analysis_state)
        
        # Construct a mutable, easy-to-analyze NetworkModel of it:
        analysis_model = NetworkModel(analysis_state)
        
        # Add it to the attack graph as a node if we need to (i.e. start state)
        if analysis_state not in attack_graph:
            attack_graph.add_node(analysis_state, label=next_label)
            next_label+=1

        # For each valid attack in that state:
        for attack in get_attacks(analysis_model, exploit_dict,
                                  attack_bindings):
            
            # Generate the successor state:
            successor_state = get_successor_state(analysis_state, attack,
                                                  exploit_dict)
            # If it didn't do anything (self loop -- generated the same state
            # it started from), skip it and go on to the next attack.
            if successor_state == analysis_state:
                continue
            
            if DEBUG: print "\nAttack: %s\n%s\n\nSuccessor state: %s\n%s" % \
                (attack, exploit_dict[attack[0]], successor_state,
                 str(analysis_state == successor_state))
            
            # If the successor state does not exist, add it to the list to
            # be analyzed on the next iteration and the attack graph.
            if successor_state in attack_graph:
                pass
            else:
                successor_states.append(successor_state)
                attack_graph.add_node(successor_state, label=next_label)
                next_label+=1
            
            # Add the state transition to the attack graph
            attack_graph.add_edge(analysis_state, successor_state,
                                  label=get_pretty_attack(attack, exploit_dict))
    # Recur (wouldn't tail call optimization be nice?)
    return generate_attack_graph(successor_states, depth-1, exploit_dict,
                                 attack_bindings, attack_graph, next_label)

# TODO: This is currently totally discrete:
def nsfactlist_from_nm(netmodel):
    """
    Returns a list of facts in the fact tuple format from a raw netmodel parse.
    """
    factlist = []
    for netmodel_fact in netmodel.facts:
        print netmodel_fact
        if netmodel_fact.type == 'quality':
            factlist.append((netmodel_fact.type, netmodel_fact.asset,
                         netmodel_fact.name, netmodel_fact.value))
        elif netmodel_fact.type == 'topology':
            factlist.append((netmodel_fact.type, netmodel_fact.source,
                         netmodel_fact.dest, netmodel_fact.name))
            if netmodel_fact.direction == '<->':
                factlist.append((netmodel_fact.type, netmodel_fact.dest,
                                 netmodel_fact.source, netmodel_fact.name))
        elif netmodel_fact.type == 'platform':
            platform_tuple = (netmodel_fact.component_type, netmodel_fact.vendor,
                              netmodel_fact.product, netmodel_fact.version,
                              netmodel_fact.update, netmodel_fact.edition,
                              netmodel_fact.lang)
            last_value_index = 0
            for i in range(len(platform_tuple)):
                if platform_tuple[i]:
                    last_value_index = i
            platform_tuple = platform_tuple[:last_value_index+1]
            print platform_tuple
            platform_name = ':'.join(platform_tuple)
            factlist.append((netmodel_fact.type, netmodel_fact.asset,
                             platform_name, platform_tuple))
    return factlist

def ns_from_nm(netmodel):
    """
    Returns a network state tuple-of-frozensets from a raw network model parse.
    """
    assets = frozenset(netmodel.assets)
    facts = frozenset(nsfactlist_from_nm(netmodel))
    return (assets, facts)

def build_attack_graph(nm_file, xp_file, depth):
    """
    Return an attack graph from netmodel/exploit files and a maximum "depth".
    """
    netmodel = ag_parser.networkmodel.parseFile(nm_file)
    exploits = ag_parser.exploits.parseFile(xp_file)
    exploit_dict = {}
    for exploit in exploits:
        exploit_dict[exploit.name] = exploit
    initial_network_state = ns_from_nm(netmodel)
    return generate_attack_graph([initial_network_state,], depth, exploit_dict,
                                 get_attack_bindings(netmodel, exploit_dict))

def main(nm_file, xp_file, depth):
    nm_file_name = os.path.split(nm_file)[-1]
    file_prefix = 'ag_' + os.path.splitext(nm_file_name)[0]
    outname = os.path.join(file_prefix, 'ag_depth%i.dot' % (depth,))
    global ag
    ag = build_attack_graph(nm_file, xp_file, int(depth))
    nx.write_dot(ag, outname)
    stategraphs = []
    for node in ag.nodes_iter():
        node_out_name = os.path.join(file_prefix, 'nm_state%i.dot' % \
                                     (ag.node[node]['label'],))
        netmodel = NetworkModel(node)
        stategraph = netmodel.get_state_graph(str(ag.node[node]['label']))
        nx.write_dot(stategraph, node_out_name)
        stategraphs.append(stategraph)
    stategraphs_union = reduce(nx.disjoint_union, stategraphs)
    sg_out_name = os.path.join(file_prefix, 'ag_sg_depth%i.dot' % (depth,))
    nx.write_dot(stategraphs_union, sg_out_name)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print 'usage: python ag_generator.py nmfile xpfile depth'
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))