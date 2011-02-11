Definitions.

%D   = [0-9]
%L   = [A-Za-z]
%WS  = ([\000-\s]|%.*)

Dig = [0-9]
Big = [A-Z]
Small = [a-z]
WS = [\000-\s]

Rules.

state : {token,{state,TokenLine}}.
predicate : {token,{predicate,TokenLine}}.
assertions : {token,{assertions,TokenLine}}.
assets : {token,{assets,TokenLine}}.
quality : {token,{quality,TokenLine}}.
topology : {token,{topology,TokenLine}}.

\= : {token, {'=', TokenLine}}.
\: : {token, {':', TokenLine}}.
\! : {token, {'!', TokenLine}}.
\; : {token, {';', TokenLine}}.
\, : {token, {',', TokenLine}}.
\. : {token, {'.', TokenLine}}.

(({Big}|{Small})({Small}|{Big}|{Dig}|_)*) : {token, {atom,TokenChars,list_to_atom(TokenChars)}}.

%{L|D}+   : {token,{atom,TokenLine,list_to_atom(TokenChars)}}.
%{D}+   : {token,{integer,TokenLine,list_to_integer(TokenChars)}}.
%[(),]  : {token,{list_to_atom(TokenChars),TokenLine}}.
{WS}+  : skip_token.

%\.[\s\t\n] : {end_token,{'$end', TokenLine}}.

Erlang code.

%atom(TokenChars) -> list_to_atom(TokenChars).

%strip(TokenChars,TokenLen) -> 
%    lists:sublist(TokenChars, 2, TokenLen - 2).

