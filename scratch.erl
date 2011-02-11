-module(scratch).
-include("networkstate.hrl").
-include("exploitpattern.hrl").
-include("attack.hrl").
-export([start/0]).

start() -> 
combinate([],3,[a,b,c,d,e])
%lists:last(L)
.

combinate(N,D,P) ->
  case D of
    0 -> lists:reverse(N);
    1 -> lists:map(fun(X) -> combinate(X,D-1,P) end,genBranches(N,P));
    _ -> lists:append(lists:map(fun(X) -> combinate(X,D-1,P) end,genBranches(N,P)))
  end.

genBranches(N,P) ->  lists:map(fun(X) -> [X] ++ N end, P).

