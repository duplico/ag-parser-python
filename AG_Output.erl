-module(AG_Output).
-include("networkstate.hrl").
-include("exploitpattern.hrl").
-include("attack.hrl").
-export([printAttack/2,printNetworkState/1,digraphToDot/2]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% printAttack()
% #attack: Attack record
% Side effect: Prints out the attack record
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
printAttack(#attack{attack_id=Attack_Id,vulnerability=Vulnerability,quality_prs=Quality_prs,
                    topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos},
            #networkstate{state_id=State_Id,assets=Assets,qualities=Qualities,topologies=Topologies}) ->
io:format("-------------------~nATTACK ~w:~w on Network State ~w~n",
  [Attack_Id,Vulnerability,State_Id]),
io:format("PreQ:~w~n",[ets:match(Quality_prs,{Attack_Id,'$1','$2','$3'})]),
io:format("PreT:~w~n",[ets:match(Topology_prs,{Attack_Id,topology,'$1','$2'})]),
io:format("PostQ:~w~n",[ets:match(Quality_pos,{Attack_Id,'$1','$2'})]),
io:format("PostT:~w~n",[ets:match(Topology_pos,{Attack_Id,'$1','$2'})]),
io:format("-------------------~n",[]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% printNetworkState()
% #networkstate: Network state record
% Side effect: Prints out the network state
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
printNetworkState(#networkstate{state_id=State_id,assets=Assets,qualities=Qualities,topologies=Topologies}) ->
io:format("NETWORK STATE: ~w~n",[State_id]),
io:format("Assets:~w~n",[{Assets,ets:match(Assets,'$1')}]),
io:format("Qualities:~w~n",[ets:match(Qualities,{quality,'$1','$2','$3'})]),
io:format("Topologies:~w~n",[ets:match(Topologies,{topology,'$1','$2','$3'})]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% digraphToDot() 
% Digraph: digraph
% Filename: String
% Side effect:  writes a digraph to the Dot format for Graphviz
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
digraphToDot(Digraph,Filename) ->
  {ok,Stream} = file:open(Filename ++ ".dot",write),
  io:format(Stream,"digraph g {~n",[]),
  lists:foreach(fun(V) -> 
                  {networkstate,{S1,S2,S3},A,P,T} = V,
                  io:format(Stream,"    \"~w\" [ label = \"~w\" ];~n",[S3,S3])
                end, digraph:vertices(Digraph)),

  lists:foreach(fun(E) ->
                  {E1,V1,V2,L} = digraph:edge(Digraph,E), 
                  {networkstate,{S1_1,S2_1,S3_1},A_1,P_1,T_1} = V1,
                  {networkstate,{S1_2,S2_2,S3_2},A_2,P_2,T_2} = V2,
                  {attack,Attack_Id,Label,Q_prs,T_prs,Q_pos,T_pos} = L,
                  io:format(Stream,"  \"~w\" -> \"~w\" [ label = \"~w\" ];~n",[S3_1,S3_2,Label])
                end, digraph:edges(Digraph)),
  io:format(Stream,"}~n",[]),
  file:close(Stream).
