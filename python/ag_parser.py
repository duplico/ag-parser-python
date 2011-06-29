from pyparsing import Word, Suppress, Literal, \
    alphanums, oneOf, ZeroOrMore, OneOrMore, Combine, Group, \
    delimitedList, Regex, Optional

# reserved = ['topology', 'quality', 'network', 'model', 'assets', 'facts', \
#             'insert', 'delete', 'exploit', 'preconditions', 'postconditions',\
#             'state', 'predicate']

# TODO: topology deletion syntax should not permit operators, only names.

real = Regex(r"[+-]?\d+(\.\d*)?").setParseAction(lambda t: float(t[0]))

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

real_assignop = oneOf(':= += -= *= /=')
tok_assignop = Literal('=')
real_relop = oneOf('== <> >= <= > <')
tok_relop = oneOf('= !=')

# TODO: make this work somehow.
hostdec = (Literal('@') | Literal('!@'))
hostdec.setParseAction(lambda a: {'@': 'up', '!@': 'down'}[str(a[0])])
host = hostdec('status') + atom + semi
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
                                            atom('value')) + semi

# Topology assignment fact: may either state a topology (token) or operate on
# its value (real)
topology_assignfact = topology_decl + Optional(real_assignop('operator') + \
                                               atom('value')) + semi

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

# Network model parser

assetlist = 'assets' + colon + Group(OneOrMore(atom + semi))('assets')
factlist = 'facts' + colon + Group(ZeroOrMore(Group(assignfact)))('facts')

networkmodel = Combine(Literal('network') + Literal('model'), joinString=' ', \
                       adjacent=False) + \
               Suppress('=') + assetlist + factlist + \
               dot

# Parser for exploit patterns

factop = oneOf('insert delete update')('operation') + assignfact
exploit = Suppress('exploit') + atom('name') + lpar + \
          Group(delimitedList(atom))('params') + rpar + Suppress('=') + \
          'preconditions' + colon + \
          Group(ZeroOrMore(Group(relfact)))('preconditions') + \
          'postconditions' + colon + \
          Group(ZeroOrMore(Group(factop)))('postconditions') + dot

exploits = OneOrMore(Group(exploit))

# Parser for state predicates
statepredicate = Combine(Literal('state') + Literal('predicate'), joinString=' ', \
                         adjacent=False) + \
                 Suppress('=') + assetlist + \
                 Group(ZeroOrMore(Group(relfact)))('facts') + dot
