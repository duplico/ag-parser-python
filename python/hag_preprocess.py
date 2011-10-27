import ag_parser
import re
import operator
#from sympy import *

def key_half_intervals(half):
    """
    half1 and half2 are strings
    """
    # ints only at the moment -- TODO
    half_re = re.compile(r'(?P<left_part>[\[\(])?(?P<num_part>([\+\-]?\d+)|([\+\-]oo))(?P<right_part>[\)\]])?')
    half_sort_keys = {'[' : 0, '(' : 1, ')' : 2, ']' : 3}
    h = half_re.match(half)
    # Assert well-formed:
    assert h
    assert operator.xor(bool(h.groupdict()['left_part']), bool(h.groupdict()['right_part']))
    half_symbol = h.groupdict()['left_part'] or h.groupdict()['right_part']
    
    sort_key_infty = 0
    sort_key_num = 0
    sort_key_half = half_sort_keys[half_symbol]
    
    if h.group('num_part') == '+oo':
        sort_key_infty = 1
    elif h.group('num_part') == '-oo':
        sort_key_infty = -1
    else: # finite
        sort_key_num = int(h.group('num_part')) # TODO
    
    return (sort_key_infty, sort_key_num, sort_key_half)

class HybridScenario(object):
    def __init__(self, nm_file, xp_file):
        self.src_nm_file = nm_file
        self_src_xp_file = xp_file
        self.src_nm = ag_parser.networkmodel.parseFile(nm_file)
        self.src_xp = ag_parser.exploits.parseFile(xp_file)
        self.intervals = dict(quality=dict(), # sets
                              topology=dict()) # sets
        
    def insert_interval(self, exploit, location, fact_type, name, interval):
        """
        Arguments:
        location - 'prec' or 'mode
        type - 'quality' or 'topology'
        name - name of the fact
        interval - sympy Interval type
        """
        if not interval:
            return # Nothing to insert, nothing to do.
        
        interval_dict[fact_type].setdefault(name, set())
        interval_set = interval_dict[fact_type][name]
        
        if interval in interval_set:
            return # Interval's already in there, nothing to do.
        
        intersecting_intervals = [i for i in interval_set
                                  if interval.intersect(i)]
        
        if not intersecting_intervals: # We have something completely new
            pass
    