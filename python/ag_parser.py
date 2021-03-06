from pyparsing import Word, Suppress, Literal, \
    alphanums, oneOf, ZeroOrMore, OneOrMore, Combine, Group, \
    delimitedList, Regex, Optional, pythonStyleComment, ParseFatalException

# reserved = ['topology', 'quality', 'network', 'model', 'assets', 'facts', \
#             'insert', 'delete', 'exploit', 'preconditions', 'postconditions',\
#             'state', 'predicate']

# TODO: topology deletion syntax should not permit operators, only names.

real = Regex(r"[+-]?\d+(\.\d*)?").setParseAction(lambda t: float(t[0]))

deriv = oneOf('-1 +1 1').setParseAction(lambda t: float(t[0]))

extended_real = real | Literal('+oo') | Literal('-oo')

interval = oneOf('[ (')('left_symbol') + extended_real('lower_limit') + \
           Suppress(Literal(',')) + extended_real('upper_limit') + \
           oneOf('] )')('right_symbol')

def validate_interval(interval):
    # Validation:
    lower_limit = interval.lower_limit
    upper_limit = interval.upper_limit
    left_symbol = interval.left_symbol
    right_symbol = interval.right_symbol
    
    if lower_limit == '+oo':
        raise ParseFatalException('Illegal interval lower limit +oo')
    if upper_limit == '-oo':
        raise ParseFatalException('Illegal interval upper limit -oo')
    if left_symbol == '[' and lower_limit == '-oo':
        raise ParseFatalException('Closed interval limit [-oo not allowed, change to open (-oo')
    if right_symbol == ']' and upper_limit == '+oo':
        raise ParseFatalException('Closed interval limit +oo] not allowed, change to open +oo)')
    if lower_limit != '-oo' and upper_limit != '+oo':
        if lower_limit >= upper_limit:
            raise ParseFatalException('Left interval limit must be less than right limit.')
    emit_intervals = []
    if left_symbol == '[':
        emit_intervals.append(lower_limit)
    if right_symbol == ']':
        emit_intervals.append(upper_limit)
    print type(lower_limit)
    emit_intervals.append((lower_limit, upper_limit))
    print emit_intervals
    return emit_intervals

interval.setParseAction(validate_interval)

cpe_valid_characters = alphanums+"-.+_~%"
cpe_atom = Word(cpe_valid_characters)
plain_atom = Word(alphanums+"._~")
atom = Word(alphanums+"._~%")
empty_atom = Word(alphanums)
cpe_type = Word('aho', exact=1)
language_tag = plain_atom # TODO: RFC 4646 compliance
dot = Suppress('.')
semi = Suppress(';')
colon = Suppress(':')
comma = Suppress(',')
lpar = Suppress('(')
rpar = Suppress(')')

group_dec = Literal('group') + Literal('(') + atom('group')('group') + Literal(')')
global_dec = Literal('global')('globl')

real_assignop = oneOf(':= += -= *= /=')
tok_assignop = Literal('=')
real_relop = oneOf('== <> >= <= > <')
tok_relop = oneOf('= !=')

# TODO: make this work somehow.
hostdec = (Literal('@') | Literal('!@'))
host = Group(Optional(hostdec('status')) + atom('name'))
# Shared grammar elements

cpe = Suppress(Literal('cpe:/')) +\
        Optional(Optional(cpe_type)('component_type') +\
        Optional(colon + Optional(cpe_atom)('vendor') +\
        Optional(colon + Optional(cpe_atom)('product') +\
        Optional(colon + Optional(cpe_atom)('version') +\
        Optional(colon + Optional(cpe_atom)('update') +\
        Optional(colon + Optional(cpe_atom)('edition') +\
        Optional(colon + Optional(language_tag)('lang'))))))))

topology_decl = Literal('topology')('type') + colon + atom('source') + \
                oneOf('-> <->')('direction') + atom('dest') + comma + \
                atom('name')

quality_decl = Literal('quality')('type') + colon + atom('asset') + \
                comma + atom('name')

# Topology relational fact: may either state a topology (token) or operate
# on its value (real)
topology_relfact = topology_decl + Optional(real_relop('operator') + \
                                            real('value')) + semi

# Topology assignment fact: may either state a topology (token) or operate on
# its value (real)
topology_assignfact = topology_decl + Optional(real_assignop('operator') + \
                                               real('value')) + semi

# Quality relational fact: may test on either the token relations (=, !=) or
# the real relations (==, <>, >=, <=)
quality_relfact = quality_decl + tok_relop('operator') + atom('value') + semi | \
                  quality_decl + real_relop('operator') + real('value') + semi

# Quality assignment fact: may either assign a token value (=) or a real value
# (:=, +=, -=, *=, /=)
quality_assignfact = quality_decl + tok_assignop('operator') + atom('value') + semi | \
                     quality_decl + real_assignop('operator') + real('value') + semi

# There's only one kind of platform fact
platform_fact = Literal('platform')('type') + colon + atom('asset') + comma + \
               cpe('platform') + semi

assignfact = topology_assignfact | quality_assignfact | platform_fact
relfact = topology_relfact | quality_relfact | platform_fact

# Modes for hybrid exploits:
mode = (topology_decl | quality_decl) + Suppress(Literal("'")) + \
       Suppress(Literal('=')) + deriv('rate') + \
       Literal('while')('guard') + interval('interval')

# Network model parser

assetlist = 'assets' + colon + Group(OneOrMore(atom + semi))('assets')
factlist = 'facts' + colon + Group(ZeroOrMore(Group(assignfact)))('facts')

assetlist.ignore(pythonStyleComment)
factlist.ignore(pythonStyleComment)

networkmodel = Combine(Literal('network') + Literal('model'), joinString=' ', \
                       adjacent=False) + \
               Suppress('=') + assetlist + factlist + \
               dot
networkmodel.ignore(pythonStyleComment)

def networkmodel_paramcheck(networkmodel):
    valid_assets = list(networkmodel.assets)
    offender = False
    
    for fact in networkmodel.facts:
        if fact.type == 'topology':
            if fact.source not in valid_assets:
                offender = fact.source
                break
            if fact.dest not in valid_assets:
                offender = fact.dest
                break
        elif fact.asset not in valid_assets:
            offender = fact.asset
            break
    if offender:
        raise ParseFatalException('Undeclared asset "%s".' % \
                             (offender,))
    return networkmodel

networkmodel.addParseAction(networkmodel_paramcheck)

# Parser for exploit patterns

factop = oneOf('insert delete update')('operation') + assignfact
exploit = Optional(global_dec) + Optional(group_dec) + \
          Suppress('exploit') + atom('name') + lpar + \
          Group(delimitedList(atom))('params') + rpar + Suppress('=') + \
          'preconditions' + colon + \
          Group(OneOrMore(Group(relfact)))('preconditions') + \
          'postconditions' + colon + \
          Group(OneOrMore(Group(factop)))('postconditions') + dot

hybrid_exploit = Suppress('hybrid exploit') + atom('name') + lpar + \
          Group(delimitedList(atom))('params') + rpar + Suppress('=') + \
          'preconditions' + colon + \
          Group(ZeroOrMore(Group(relfact)))('preconditions') + \
          'postconditions' + colon + \
          Group(ZeroOrMore(Group(factop)))('postconditions') + \
          'modes' + colon + Group(OneOrMore(Group(mode) + semi))('modes') + dot

def exploit_paramcheck(exploit):
    valid_parameters = list(exploit.params)
    offender = False
    
    for fact in exploit.preconditions + exploit.postconditions:
        if fact.type == 'topology':
            if fact.source not in valid_parameters:
                offender = fact.source
                break
            if fact.dest not in valid_parameters:
                offender = fact.dest
                break
        elif fact.asset not in valid_parameters:
            offender = fact.asset
            break
    if offender:
        raise ParseFatalException('Unknown asset %s in exploit %s.' % \
                             (offender, exploit.name))
    return exploit

exploit.setParseAction(exploit_paramcheck)
hybrid_exploit.setParseAction(exploit_paramcheck)

exploits = OneOrMore(Group(exploit | hybrid_exploit))
exploits.ignore(pythonStyleComment)

# Parser for state predicates
statepredicate = Combine(Literal('state') + Literal('predicate'), joinString=' ', \
                         adjacent=False) + \
                 Suppress('=') + assetlist + \
                 Group(OneOrMore(Group(relfact)))('facts') + dot
