Nonterminals root assetlist factlist fact.
Terminals 'network' 'model' 'assets' 'facts' 'quality' 'topology' atom '=' ';' ',' ':' '.' .
Rootsymbol root.
Endsymbol '$end'.

root -> 'network' 'model' '=' 'assets' ':' assetlist 'facts' ':' factlist '.': {tl(lists:reverse(lists:flatten('$6'))),tl(lists:flatten('$9'))}.

assetlist -> assetlist atom ';' : [element(3,'$2'),'$1'].
assetlist -> '$empty' : nil.

factlist -> fact factlist : ['$2','$1'].
factlist -> '$empty' : nil.

fact -> 'quality' ':' atom ',' atom ',' atom ';' : {quality,element(3,'$3'),element(3,'$5'),element(3,'$7')}.
fact -> 'topology' ':' atom ',' atom ',' atom ';' : {topology,element(3,'$3'),element(3,'$5'),element(3,'$7')}.
