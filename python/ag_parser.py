# TODO: refactor on paper.

from pyparsing import Word, Suppress, Literal, \
    alphanums, oneOf, ZeroOrMore, OneOrMore, Combine, Group, \
    delimitedList, Regex, Optional

# reserved = ['topology', 'quality', 'network', 'model', 'assets', 'facts', \
#             'insert', 'delete', 'exploit', 'preconditions', 'postconditions',\
#             'state', 'predicate']

real = Regex(r"[+-]?\d+(\.\d*)?").setParseAction(lambda t: float(t[0]))

atom = Word(alphanums+"_:/")
dot = Suppress('.')
semi = Suppress(';')
colon = Suppress(':')
comma = Suppress(',')
lpar = Suppress('(')
rpar = Suppress(')')

assignop = oneOf('= := += -= *= /=')
relop = oneOf('== != >= <=')

# Shared grammar elements

topology_fact = Literal('topology')('type') + colon + atom('source') + \
                oneOf('-> <->')('direction') + atom('dest') + comma + \
                atom('name') + \
                Optional((relop | assignop)('operator') + real('value')) + semi
quality_fact = Literal('quality')('type') + colon + atom('asset') + comma + \
               atom('name') + (relop | assignop)('operator') + atom('value') + \
               semi
fact = topology_fact | quality_fact

# Network model parser

assetlist = 'assets' + colon + Group(OneOrMore(atom + semi))('assets')
factlist = 'facts' + colon + Group(ZeroOrMore(Group(fact)))('facts')
# TODO: Assert that the assignops are all '=' or ':=', no relops allowed

networkmodel = Combine(Literal('network') + Literal('model'), joinString=' ', \
                       adjacent=False) + \
               Suppress('=') + assetlist + factlist + \
               dot

# Parser for exploit patterns

factop = oneOf('insert delete update')('operation') + fact
exploit = Suppress('exploit') + atom('name') + lpar + \
          Group(delimitedList(atom))('params') + rpar + Suppress('=') + \
          'preconditions' + colon + Group(ZeroOrMore(Group(fact)))('preconditions') + \
          'postconditions' + colon + Group(ZeroOrMore(Group(factop)))('postconditions') + dot
exploits = OneOrMore(Group(exploit))
# TODO: preconditions: no assignops allowed
# TODO: postconditions: no relops allowed

# Parser for state predicates

statepredicate = Combine(Literal('state') + Literal('predicate'), joinString=' ', \
                         adjacent=False) + \
                 Suppress('=') + assetlist + factlist + \
                 dot
# TODO: no assignops allowed