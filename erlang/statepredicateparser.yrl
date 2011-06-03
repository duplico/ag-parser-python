Nonterminals root assetlist assertionlist parity assertion.
Terminals 'state' 'predicate' 'assets' 'assertions' 'quality' 'topology' atom '=' ';' ',' ':' '!' '.' .
Rootsymbol root.
Endsymbol '$end'.

root -> 'state' 'predicate' '=' 'assets' ':' assetlist 'assertions' ':' assertionlist '.': {tl(lists:reverse(lists:flatten('$6'))),tl(lists:flatten('$9'))}.

assetlist -> assetlist atom ';' : [element(3,'$2'),'$1'].
assetlist -> '$empty' : nil.

assertionlist -> assertion assertionlist : ['$2','$1'].
assertionlist -> '$empty' : nil.

parity -> '!' :  not_exists.
parity -> '$empty': exists. 

assertion -> parity 'quality' ':' atom ',' atom ',' atom ';' : {'$1',quality,element(3,'$4'),element(3,'$6'),element(3,'$8')}.
assertion -> parity 'topology' ':' atom ',' atom ',' atom ';' : {'$1',topology,element(3,'$4'),element(3,'$6'),element(3,'$8')}.
