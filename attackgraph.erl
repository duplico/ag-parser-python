-module(attackgraph).
-include("networkstate.hrl").
-include("exploitpattern.hrl").
-include("attack.hrl").
-export([start/0,getAssets/1,getQualities/1,getTopologies/1,
getAttPreQs/1,getAttPreTs/1,getAttPostQs/1,getAttPostTs/1,
tagZ/1,bindlist/2,boundParam/2,attackGen/2]).

start() -> 
Q1 = #quality{asset='host1',property='OS',value='WinXP'},
Q2 = #quality{asset='host2',property='OS',value='MacOSX'},
Q3 = #quality{asset='host3',property='OS',value='Unix'},
T1 = #topology{asset1='host1',asset2='host2',relationship='trust'},
N1 = #networkstate{assets=['host1','host2','host3'],qualities=[Q1,Q2,Q3],topologies=[T1]},
QE1 = #quality_e{asset_var='h1',property='OS',value='WinXP'},
QE2 = #quality_e{asset_var='h2',property='OS',value='Unix'},
QE3 = #quality_e{asset_var='h2',property='App',value='corrupt'},
TE1 = #topology_e{asset1_var='h1',asset2_var='h2',relationship='trust'},
EP1 = #exploitpattern{vulnerability='hack',parameters=['h1','h2'],quality_prc=[QE1,QE2],topology_prc=[TE1],quality_poc=[{'insert',QE3}],topology_poc=[]},
{N1,EP1},
BL = [{'host1','h1'},{'host2','h2'},{'host3','h3'}],
Attack = attackGen(EP1,BL),
{
EP1,Attack
}.

%NETWORK STATE ACCESSOR FUNCTIONS
getAssets(#networkstate{assets=Assets,qualities=Qualities,topologies=Topologies}) -> Assets.

getQualities(#networkstate{assets=Assets,qualities=Qualities,topologies=Topologies}) -> Qualities.

getTopologies(#networkstate{assets=Assets,qualities=Qualities,topologies=Topologies}) -> Topologies.

%ATTACK ACCESSOR FUNCTIONS
getAttPreQs(#attack{vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) -> Quality_prs.

getAttPreTs(#attack{vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) -> Topology_prs.

getAttPostQs(#attack{vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) -> Quality_pos.

getAttPostTs(#attack{vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) -> Topology_pos.

%ATTACK GENERATION FUNCTIONS

%Attack Generation:
attackGen(#exploitpattern{vulnerability=Vulnerability_E,parameters=Parameters,quality_prc=Quality_prc,topology_prc=Topology_prc,quality_poc=Quality_poc,topology_poc=Topology_poc}, A4I_list) ->
          #attack{vulnerability=Vulnerability_E,quality_prs=lists:map((q_e2q(A4I_list)),Quality_prc),topology_prs=lists:map((t_e2t(A4I_list)),Topology_prc),quality_pos=lists:map((qpoc_e2qpoc(A4I_list)),Quality_poc),topology_pos=lists:map((tpoc_e2tpoc(A4I_list)),Topology_poc)}. 
         
%EXPLOIT2ATTACK FUNCTIONS

tagZ(Z) ->
  fun({X,Y}) -> {X,Y,Z} end.

bindlist(B,Param) ->
  lists:foldl( fun({X,Y,Z},{A1,A2,R}) -> 
                 case Z of 
                   Y -> {0,0,X};
                   _ -> {0,0,R}
                 end 
                end,
                 {0,0,Param},
                 lists:map((tagZ(Param)),B)).

boundParam(B,Param) ->
  element(3,bindlist(B,Param)).
  
q_e2q(A4I_list) -> 
  fun(#quality_e{asset_var=Asset_var,property=Property,value=Value}) ->
  #quality{asset=boundParam(A4I_list,Asset_var),property=Property,value=Value} end.

t_e2t(A4I_list) -> 
  fun(#topology_e{asset1_var=Asset1_var,asset2_var=Asset2_var,relationship=Relationship}) ->
    A1 = boundParam(A4I_list,Asset1_var),
    A2 = boundParam(A4I_list,Asset2_var),
    #topology{asset1=A1,asset2=A2,relationship=Relationship} end.

qpoc_e2qpoc(A4I_list) -> 
  fun({Operation,#quality_e{asset_var=Asset_var,property=Property,value=Value}}) ->
  {Operation,#quality{asset=boundParam(A4I_list,Asset_var),property=Property,value=Value}} end.

tpoc_e2tpoc(A4I_list) -> 
  fun({Operation,#topology_e{asset1_var=Asset1_var,asset2_var=Asset2_var,relationship=Relationship}}) ->
    A1 = boundParam(A4I_list,Asset1_var),
    A2 = boundParam(A4I_list,Asset2_var),
    {Operation,#topology{asset1=A1,asset2=A2,relationship=Relationship}} end.

%ATTACK STATE CHECKING FUNCTIONS

checkQ(Attack,Networkstate) ->
  Q_a = sets:from_list(getAttPreQs(Attack)),
  Q_n = sets:from_list(getQualities(Networkstate)),
  sets:issubset(Q_a,Q_n).

checkT(Attack,Networkstate) ->
  T_a = sets:from_list(getAttPreTs(Attack)),
  T_n = sets:from_list(getTopologies(Networkstate)),
  sets:issubset(T_a,T_n).

%NEXT STATE FUNCTIONS

nextState(Attack,Networkstate) ->
  case (checkQ(Attack,Networkstate) andalso checkT(Attack,Networkstate)) of
    true -> #networkstate{assets=getAssets(Networkstate),qualities=(update(getAttPostQs(Attack),getQualities(Networkstate))),topologies=(update(getAttPostTs(Attack),getTopologies(Networkstate)))};
    false -> Networkstate
  end.

update(Post,S) -> 
  case Post of
    {'insert',X} -> lists:append(S,[X]);
    {'delete',X} -> lists:delete(X,S)
  end.

%oldstart

%q_e2q({'host1','h1'},QE1),
%q_e2q_curried({'host1','h1'}),
%(q_e2q_curried({'host1','h1'}))(QE1),
%t_e2t({'host2','h2'},TE1),
%q_e2q_list({'host1','h1'},[QE1,QE2,QE3]),
%q_e2q_list_curried([QE1,QE2,QE3]),
%(q_e2q_list_curried([QE1,QE2,QE3]))({'host1','h1'}),
%q_e2q_list_curried([QE1,QE2,QE3]),
%(q_e2q_list_curried([QE1,QE2,QE3]))({'host1','h1'}),
%q_e2q_list2([{'host1','h1'},{'host2','h2'},{'host3','h3'}],[QE1,QE2,QE3])}




%old fn definitions
%q_e2q_list2(Bind_vector,Q_list) -> lists:map(q_e2q_list_curried(Q_list),Bind_vector).

%q_e2q_list_curried(Q_list) ->
%  fun({A,I}) -> q_e2q_list({A,I},Q_list) end.
 
%q_e2q_list({A,I},Q_list) -> lists:map(q_e2q_curried({A,I}),Q_list).

%q_e2q_curried({A,I}) ->
%  fun(Q_e) -> q_e2q({A,I},Q_e) end.

%q_e2q({A,I},#quality_e{asset_var=Asset_var,property=Property,value=Value}) ->
%  #quality{asset=bind({A,I},Asset_var),property=Property,value=Value}.

%t_e2t({A,I},#topology_e{asset1_var=Asset1_var,asset2_var=Asset2_var,relationship=Relationship}) ->
%    A1 = bind({A,I},Asset1_var),
%    A2 = bind({A,I},Asset2_var),
%    #topology{asset1=A1,asset2=A2,relationship=Relationship}.

