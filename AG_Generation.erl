-module(AG_Generation).
-include("networkstate.hrl").
-include("exploitpattern.hrl").
-include("attack.hrl").
-export([buildAttackGraph/14]).

%MAIN ATTACK GENERATION ROUTINES
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% buildAttackGraph()
% EL: Exploit List
% NL: Network State List (active states only)
% Network_state_table: ETS Table containing all Network State records
% Assets_table: ETS Table containing all Asset records
% Qualities_table: ETS Table containing all Qualities records
% Topologies_table: ETS Table containing all Topologies records
% Attack_table: ETS Table containing all Attack records
% Q_prs: ETS Table containing all Quality Precondition Attack records
% T_prs: ETS Table containing all Topology Precondition Attack records
% Q_pos: ETS Table containing all Quality Postcondition Attack records
% T_pos: ETS Table containing all Topology Postcondition Attack records
% Attack_graph: Digraph repn of attack graph (V=network states, E=attacks)
% Table_vertex_index: ETS Table associating Network States with Vertices
% Depth: integer signifying how many recursions to expand the graph
%  a negative value for depth indicates to generate the graph
%  until no new network states are computed
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
buildAttackGraph(EL,NL,Network_state_table,Assets_table,Qualities_table,
                 Topologies_table,Attack_table,Q_prs,T_prs,Q_pos,T_pos,
                 Attack_graph,Table_vertex_index,Depth) ->
  case doneBuilding(Depth,NL) of 
  false -> NL2 = lists:append(lists:map(fun(S)->
    computeNextStates(computeAttacks(EL,S,Attack_table,Q_prs,T_prs,Q_pos,T_pos),
                            S,Network_state_table,Assets_table,Qualities_table,
                            Topologies_table,Attack_graph,Table_vertex_index) 
                            end,NL)),
    buildAttackGraph(EL,NL2,Network_state_table,Assets_table,Qualities_table,
                          Topologies_table,Attack_table,Q_prs,T_prs,Q_pos,T_pos,
                           Attack_graph,Table_vertex_index,Depth-1);
  true -> true
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% doneBuilding()
% Depth: Integer
% Network_states_list: List of Network State Records
% Return value: Boolean
% Returns true if Depth is 0 or if the network states list is empty
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
doneBuilding(Depth,Network_states_list) ->
Depth == 0 orelse Network_states_list == [].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% computeAttacks()
% EL: Exploit List
% N: Network state
% Attack_table: ETS of Attacks
% Q_prs: Precondition quality table for Attacks
% T_prs: Precondition topology table for Attacks
% Q_pos: Postcondition quality table for Attacks
% T_pos: Postcondition topolgoy table for Attacks
% Return value: list of viable attacks of Exploit List EL from state N 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
computeAttacks(EL,N,Attack_table,Q_prs,T_prs,Q_pos,T_pos) ->
  lists:append(lists:map((fun(E)-> computeAttacksfromExploit(E,N,Attack_table,Q_prs,T_prs,Q_pos,T_pos) end),EL)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% computeAttacksfromExploit()
% E: Exploit
% N: Network state
% Attack_table: ETS Table containing Attack records
% Q_prs: Precondition quality table for Attacks
% T_prs: Precondition topology table for Attacks
% Q_pos: Postcondition quality table for Attacks
% T_pos: Postcondition topolgoy table for Attacks
% Return value: list of viable attacks of Exploit E from state N 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
computeAttacksfromExploit(E,N,Attack_table,Q_prs,T_prs,Q_pos,T_pos) -> 
  Viable_attacks = genExploitBindings(E,N,Q_prs,T_prs,Q_pos,T_pos),
  lists:foreach(fun(A) -> ets:insert(Attack_table,A) end,Viable_attacks),
  Viable_attacks.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% computeNextStates()
% AL: Attack List
% N: Network State
% Network_state_table: ETS Table containing all Network State records
% Assets_table: ETS Table containing all Asset records
% Qualities_table: ETS Table containing all Qualities records
% Topologies_table: ETS Table containing all Topologies records
% AG: Digraph repn of attack graph (V=Network states, E=Attacks)
% TVI: ETS Table associating Network States with Vertices
% Side effects:
%     It adds the attack edges to the digraph for all viable attacks
%     It adds vertices to the attack graph for new network states
%     It adds new network states to the Network State Table
% Return value: A list of new network states
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
computeNextStates(AL,N,Network_state_table,Assets_table,Qualities_table,
                  Topologies_table,AG,TVI) ->
  [[V]] = ets:match(TVI,{N#networkstate.state_id,'$1'}),
  NL = lists:map(fun(A) -> 
               New_state = nextState(A,N),
% case on findNetworkState(New_state,Network_state_table)
%      false (no matching state exists) => 
%           1) Add New_state to the Network_state_table and 
%           2) Add Vertex for New_state and Edge for Attack to attack graph
%      _ (#networkstate.state_id; matching state found) =>
%           Add edge for network state from findNetworkState to attack graph 
               S = findNetworkState(New_state,Network_state_table),
               case S of
                  false -> Installed_network_state = 
                             AG_Table_Management:installNetworkState(Network_state_table,New_state,
                              Assets_table,Qualities_table,Topologies_table),
                           V2 = digraph:add_vertex(AG,Installed_network_state),
                           digraph:add_edge(AG,V,V2,A),
                           ets:insert(TVI,
                            {Installed_network_state#networkstate.state_id,V2}),
                           Installed_network_state; 
                  _ ->     {State_id,V2} = hd(ets:lookup(TVI,S)),
                           digraph:add_edge(AG,V,V2,A),
                           false 
                   end 
                 end,AL),
  NL2 = lists:filter(fun(X) -> X /= false end, NL),
  lists:foreach(fun(S) -> ets:insert(Network_state_table,S) end,
                lists:filter(( fun(X) -> X /= false end),NL2)),
  NL2.
  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% addToAttackGraph(Attack_graph,Attack,V1,New_network_state)
%   Attack_graph: digraph of attack graph (V = Network states, E = Attacks)
%   Attack: #attack record
%   V1: vertex (labeled with a network state)
%   New_network_state: #networkstate
%     creates a new vertex (V2), and an edge labelled with the Attack 
%   Return value: edge labelled with the Attack
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
addToAttackGraph(Attack_graph,Attack,V1,New_network_state) ->
  V2 = digraph:add_vertex(Attack_graph,New_network_state),
  digraph:add_edge(Attack_graph,V1,V2,Attack).
  
%NETWORK STATE ACCESSOR FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getAssets(Network State Record) -> ETS:Assets
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getAssets(#networkstate{state_id=State_id,assets=Assets,qualities=Qualities,topologies=Topologies}) -> Assets.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getQualities(Network State Record) -> ETS:Qualities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getQualities(#networkstate{state_id=State_id,assets=Assets,qualities=Qualities,topologies=Topologies}) -> Qualities.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getTopologies(Network State Record) -> ETS:Topologies
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getTopologies(#networkstate{state_id=State_id,assets=Assets,qualities=Qualities,topologies=Topologies}) -> Topologies.

%NETWORK STATE COMPARISON FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% equalsA(Assets Table, Assets Table) -> Boolean
% Returns true if the contents of the Assets Tables are equal 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
equalsA(Assets_table,State_Id_1,State_Id_2) ->
Al1 = lists:sort(ets:match(Assets_table,{State_Id_1,'$1'})),
Al2 = lists:sort(ets:match(Assets_table,{State_Id_2,'$2'})),
%io:format("equalsAsset:~n~w~n-------~w~n",[Al1,Al2]),
Al1 == Al2.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% equalsAtmp(Assets Table, Assets, State_Id_2) -> Boolean
% Returns true if the contents of the Assets Tables are equal 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
equalsATmp(Assets_table,Assets,State_Id_2) ->
Al1 = sets:from_list([[X] || {_,X} <- sets:to_list(Assets)]),
Al2 = sets:from_list(ets:match(Assets_table,{State_Id_2,'$2'})),
%io:format("equalsAsset:~n~w~n-------~w~n",[Al1,Al2]),
Al1 == Al2.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% equalsQ(Qualities_table, State_Id_1, State_Id_2) -> Boolean
% Returns true if the contents of the Qualities Tables are equal 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
equalsQ(Qualities_table, State_Id_1, State_Id_2) ->
Ql1 = lists:sort(ets:match(Qualities_table,{'_',State_Id_1,'$1','$2'})),
Ql2 = lists:sort(ets:match(Qualities_table,{'_',State_Id_2,'$3','$4'})),
%io:format("equalsQualities:~n~w~n-------~w~n",[Ql1,Ql2]),
Ql1 == Ql2.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% equalsQTmp(Qualities_table, Qualities, State_Id_2) -> Boolean
% Returns true if the contents of the Qualities Tables are equal 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
equalsQTmp(Qualities_table, Qualities, State_Id_2) ->
Qs1 = sets:from_list([[X,Y] || {_,_,X,Y} <- sets:to_list(Qualities)]),
Qs2 = sets:from_list(ets:match(Qualities_table,{'_',State_Id_2,'$1','$2'})),
%io:format("equalsQualities:~n~w~n-------~w~n",[Ql1,Ql2]),
Qs1 == Qs2.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% equalsT(Topologies_table, State_Id_1, State_Id_2) -> Boolean
% Returns true if the contents of the Topologies Tables are equal 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
equalsT(Topologies_table, State_Id_1, State_Id_2) ->
Tl1 = lists:sort(ets:match(Topologies_table,{'_',State_Id_1,'$1','$2'})),
Tl2 = lists:sort(ets:match(Topologies_table,{'_',State_Id_2,'$3','$4'})),
%io:format("equalsTopologies:~n~w~n-------~w~n",[Tl1,Tl2]),
Tl1 == Tl2.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% equalsTTmp(Topologies_table, Topologies, State_Id_2) -> Boolean
% Returns true if the contents of the Topologies Tables are equal 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
equalsTTmp(Topologies_table, Topologies, State_Id_2) ->
Ts1 = sets:from_list([[X,Y] || {_,_,X,Y} <- sets:to_list(Topologies)]),
Ts2 = sets:from_list(ets:match(Topologies_table,{'_',State_Id_2,'$1','$2'})),
%io:format("equalsTopologies:~n~w~n-------~w~n",[Ts1,Ts2]),
Ts1 == Ts2.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% equalsNetworkState(Network State, Network State) 
% Deep value comparison of two network states
% Compares Topologies, Qualities and Asset table entries
% based on the two state ids.
% Used to avoid perpetual construction of identical states
%   via reapplication of same attack.  	
% Return value: Boolean
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
equalsNetworkState(#networkstate{state_id=State_id1,assets=Assets1,qualities=Qualities1,topologies=Topologies1},#networkstate{state_id=State_id2,assets=Assets2,qualities=Qualities2,topologies=Topologies2}) ->
  equalsT(Topologies1,State_id1,State_id2) andalso
  equalsQ(Qualities1,State_id1,State_id2) andalso 
  equalsA(Assets1,State_id1,State_id2).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% equalsNetworkStateTmp(Network State, Network State) 
% Deep value comparison of two network states
% Compares Topologies, Qualities and Asset table entries
% based on the two state ids.
% Used to avoid perpetual construction of identical states
%   via reapplication of same attack.  	
% Return value: Boolean
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
equalsNetworkStateTmp(#networkstate{state_id=State_id1,assets=Assets1,qualities=Qualities1,topologies=Topologies1},#networkstate{state_id=State_id2,assets=Assets2,qualities=Qualities2,topologies=Topologies2}) ->
  equalsTTmp(Topologies2,Topologies1,State_id2) andalso
  equalsQTmp(Qualities2,Qualities1,State_id2) andalso 
  equalsATmp(Assets2,Assets1,State_id2).

%ATTACK ACCESSOR FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getAttPreQs(Attack Record) -> ETS:Quality_prs
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getAttPreQs(#attack{attack_id=Attack_Id,vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) -> Quality_prs.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getAttPreTs(Attack Record) -> ETS:Topology_prs
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getAttPreTs(#attack{attack_id=Attack_Id,vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) -> Topology_prs.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getAttPostQs(Attack Record) -> ETS:Quality_pos
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getAttPostQs(#attack{attack_id=Attack_Id,vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) ->
  ets:match(Quality_pos,{Attack_Id,'_','$1','$2'}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getAttPostTs(Attack Record) -> ETS:Topology_pos
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getAttPostTs(#attack{attack_id=Attack_Id,vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) -> 
  ets:match(Topology_pos,{Attack_Id,'_','$1','$2'}).

%EXPLOIT PATTERN ACCESSOR FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getExploitParamLength (Exploit Pattern) -> Integer
% Returns the length of the parameter list for an 
%   exploit pattern
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getExploitParamLength(#exploitpattern{exploit_id=Exploit_Id,
                       vulnerability=Vulnerabilty,
                       parameters=Parameters,quality_prc=Quality_prc,
                       topology_prc=Topology_prc,quality_poc=Quality_poc,
                       topology_poc=Topology_poc}) 
       -> length(Parameters).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getExploitParams (Exploit Pattern) -> List of Parameters 
% Returns the parameter list for an exploit pattern
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getExploitParams(#exploitpattern{exploit_id=Exploit_Id,
                       vulnerability=Vulnerabilty,
                       parameters=Parameters,quality_prc=Quality_prc,
                       topology_prc=Topology_prc,quality_poc=Quality_poc,
                       topology_poc=Topology_poc}) 
       -> Parameters. 

%ATTACK GRAPH GENERATION FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% checkNetworkState()
% Network_state: Network State Record
% Attack: Attack Record
% Return value: Boolean
% Tests to see if an attack is viable under the following constraints:
%  1) Preconditions for qualities and topologies must be satisfied
%     by the network state (checkQ and checkT validate this)
%  2) Postconditions for qualities OR topologies must be different, 
%     i.e., the attack must CHANGE the network state somehow.
%     (checkPostQ and checkPostT validate this)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
checkNetworkState(Network_state,Attack) -> 
  checkQ(Attack,Network_state) 
   andalso 
  checkT(Attack,Network_state)
   andalso 
  (checkPostQ(Attack,Network_state)
   orelse 
  checkPostT(Attack,Network_state)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% testAttack()
% Network_state: Network State Record
% Attack: Attack Record
% Return value: Boolean
% Tests to see if an attack is viable.
% If so it returns true.  If not, it deletes Attack Elements from
% appropriate tables and returns false.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
testAttack(Network_state, Attack) ->
  case checkNetworkState(Network_state,Attack) of
    true -> true;
    false -> deleteAttackElements(Attack), false
  end.

%PARAMETER BINDING FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% genExploitBindings(Exploit Pattern, Network State) -> List of Bindings 
% Takes in an Exploit Pattern and Network State; returns a list
%   of bindings - elements of the form {Argument,Parameter}
%   for those bindings whose pattern in the exploit matches
%   that in the prevailing Network State (checks Qualities and Topologies)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
genExploitBindings(E,N,Q_prs,T_prs,Q_pos,T_pos) ->
  EParamLen = getExploitParamLength(E),
  AssetsinN = ets:match(getAssets(N),{N#networkstate.state_id,'$1'}),
  AssetList = lists:map(fun(X)->X end, lists:flatten(AssetsinN)),
  AssetCombos = combinate([],EParamLen,AssetList),
  BL = lists:map((fun(X) -> lists:zip(X,getExploitParams(E)) end),AssetCombos),
%  io:format("BL:===============~n~w~n===============",[BL]),
  Attacks = lists:map(fun(X) -> attackGen(E,N,X,Q_prs,T_prs,Q_pos,T_pos) end,BL),
  Viable_attacks = lists:filter(fun(A) -> 
                                 case A of 
                                   false -> false;
                                   _ -> true
                                 end
                               end, Attacks),
  Viable_attacks.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% combinate(N = List of combinations, D = Depth,P = arguments)
%            -> List of combinations 
% Generate all permutations of a List
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
combinate(N,D,P) ->
  case D of
    0 -> lists:reverse(N);
    1 -> lists:map(fun(X) -> combinate(X,D-1,P) end,genBranches(N,P));
    _ -> lists:append(lists:map(fun(X) -> combinate(X,D-1,P) end,genBranches(N,P)))
  end.

genBranches(N,P) ->  lists:map(fun(X) -> [X] ++ N end, P).

%ATTACK CONSTRUCTION FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% attackGen(Exploit Pattern Record, Bind List,
%  Q_prs Table, T_prs Table, Q_pos Table, T_pos Table) -> Attack Record 
% Transforms an exploit pattern into an attack by binding
%   attack arguments (assets) to exploit parameters (asset variables)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%Attack Generation:
attackGen(#exploitpattern{exploit_id=Exploit_Id,vulnerability=Vulnerability_E,
                          parameters=Parameters,
                          quality_prc=Quality_prc,topology_prc=Topology_prc,
                          quality_poc=Quality_poc,topology_poc=Topology_poc}, 
           Network_state,A4I_list,Q_prs,T_prs,Q_pos,T_pos) 
    ->
         Attack_Id = getNewId(),
         Q_pre_exp_list = ets:match(Quality_prc,{quality_e,Exploit_Id,'$1','$2'}), 
         PreQs = lists:map((q_e2q(A4I_list)),Q_pre_exp_list),
         T_pre_exp_list = ets:match(Topology_prc,{topology_e,Exploit_Id,'$1','$2'}),
         PreTs = lists:map((t_e2t(A4I_list)),T_pre_exp_list),
         Q_post_exp_list_all = lists:flatten(ets:match(Quality_poc,'$1')), 
         Q_post_exp_list = [{O,{quality_e,E_Id,AP,V}} || {O,{quality_e,E_Id,AP,V}} <- Q_post_exp_list_all,E_Id == Exploit_Id],
         PostQs = lists:map((qpoc_e2qpoc(A4I_list)),Q_post_exp_list),
         T_post_exp_list_all = lists:flatten(ets:match(Topology_poc,'$1')),
         T_post_exp_list =[{O,{topology_e,E_Id,AA,R}} || {O,{topology_e,E_Id,AA,R}} <- T_post_exp_list_all,E_Id == Exploit_Id],
% io:format("T_post_exp_list:====~n~w~n======~n",[T_post_exp_list]),
         PostTs = lists:map((tpoc_e2tpoc(A4I_list)),T_post_exp_list),
         ets:insert(Q_prs,lists:map(fun({W,X,Y,Z})->{Attack_Id,Exploit_Id,X,Y,Z} end,PreQs)),
         ets:insert(T_prs,lists:map(fun({W,X,Y,Z})->{Attack_Id,Exploit_Id,X,Y,Z} end,PreTs)),
         ets:insert(Q_pos,lists:map(fun({X,Y})->{Attack_Id,Exploit_Id,X,Y} end,PostQs)),
         ets:insert(T_pos,lists:map(fun({X,Y})->{Attack_Id,Exploit_Id,X,Y} end,PostTs)),
         Attack = #attack{attack_id=Attack_Id,
                  vulnerability=Vulnerability_E,
                  quality_prs=Q_prs,
                  topology_prs=T_prs,
                  quality_pos=Q_pos,
                  topology_pos=T_pos}, 
          case testAttack(Network_state,Attack) of
            true -> Attack;
            false -> false
          end.       
         
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% tagZ(Z) -> f:({X,Y}) -> (X,Y,Z}
% returns a function that tags a tuple with a 3rd element 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
tagZ(Z) ->
  fun({X,Y}) -> {X,Y,Z} end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% bindlist(B,Param) -> {0,0,Z}
% B is a list of binding pairs, a and i to bind
%   in expression e, as in (a/i) e 
% Param is the target to bind
% the value returned is a triple, with the third
% element being the appropriate substitution result
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
bindlist(B,Param) ->
  lists:foldl( fun({X,Y,Z},{A1,A2,R}) -> 
                 case Z of 
                   Y -> {0,0,X};
                   _ -> {0,0,R}
                 end 
                end,
                 {0,0,Param},
                 lists:map((tagZ(Param)),B)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% boundParam(B,Param) -> Z
% B is a list of binding pairs, a and i to bind
%   in expression e, as in (a/i) e 
% Param is the target to bind
% Z is the correct binding (or Param if no binding)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
boundParam(B,Param) ->
  element(3,bindlist(B,Param)).
  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% q_e2q(list:A4I_list) -> ( fun(Quality_e Record) -> Quality Record )
% Transform an exploit quality into a network quality
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
q_e2q(A4I_list) -> 
  fun([{Asset_var,Property},Value]) ->
  #quality{asset_prop={boundParam(A4I_list,Asset_var),Property},value=Value} end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% t_e2t(list:A4I_list) -> ( fun(Topology_e Record) -> Topology Record )
% Transform an exploit topology into a network topology
% Return value: A function that turns a topology_e record
%  into a topology record
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
t_e2t(A4I_list) -> 
  fun([{Asset1_var,Asset2_var},Relationship]) ->
    A1 = boundParam(A4I_list,Asset1_var),
    A2 = boundParam(A4I_list,Asset2_var),
    #topology{assets={A1,A2},relationship=Relationship} end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% qpoc_e2qpoc(list:A4I_list) -> ( fun(Quality_e Record) -> Quality Record )
% Return a function to Transform an exploit quality postcondition into 
%  an attack quality postcondition
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
qpoc_e2qpoc(A4I_list) -> 
  fun({Operation,{quality_e,Exploit_Id,{Asset_var,Property},Value}}) ->
  {Operation,#quality{asset_prop={boundParam(A4I_list,Asset_var),Property},value=Value}} end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% tpoc_e2tpoc(list:A4I_list) -> ( fun(Topology_e Record) -> Topology Record )
% Return a function to Transform an exploit topology postcondition into 
%  an attack topology postcondition
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
tpoc_e2tpoc(A4I_list) -> 
  fun({Operation,{topology_e,Exploit_Id,{Asset1_var,Asset2_var},Relationship}}) ->
    A1 = boundParam(A4I_list,Asset1_var),
    A2 = boundParam(A4I_list,Asset2_var),
    {Operation,#topology{assets={A1,A2},relationship=Relationship}} end.

%ATTACK STATE CHECKING FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% checkQ(Attack Record, Network State Record) -> Boolean
% True if the attack qualities are all found in the network state
% False otherwise
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
checkQ(Attack,Network_state) ->
  Network_state_Id = Network_state#networkstate.state_id,
  Attack_Id = Attack#attack.attack_id,
  Quality_prs = getAttPreQs(Attack),
  Q_prs_list = ets:match(Quality_prs,{Attack_Id,'_',undefined,'$2','$3'}),
%io:format("Q_prs_list------~n~w~n--------~n",[Q_prs_list]),
  Qualities = getQualities(Network_state),
  Qs = ets:match(Qualities,{quality,Network_state_Id,'$1','$2'}),
%io:format("Qs------~n~w~n--------~n",[Qs]),

  Q_a = sets:from_list(Q_prs_list),
  Q_n = sets:from_list(Qs),

  Result = sets:is_subset(Q_a,Q_n),
%  io:format("checkQ result is ~w~n",[Result]),
  Result.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% checkT(Attack Record, Network State Record) -> Boolean
% True if the attack topologies are all found in the network state
% False otherwise
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
checkT(Attack,Network_state) ->
  Network_state_Id = Network_state#networkstate.state_id,
  Attack_Id = Attack#attack.attack_id,

  Topology_prs = getAttPreTs(Attack),
  T_prs_list = ets:match(Topology_prs,{Attack_Id,'_',undefined,'$2','$3'}),
%io:format("T_prs_list------~n~w~n--------~n",[T_prs_list]),
  Topologies = getTopologies(Network_state),
  Ts = ets:match(Topologies,{topology,Network_state_Id,'$1','$2'}),
%io:format("Ts------~n~w~n--------~n",[Ts]),

  T_a = sets:from_list(T_prs_list),
  T_n = sets:from_list(Ts),

  Result = sets:is_subset(T_a,T_n),
% io:format("checkT result is ~w~n",[Result]),
  Result.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% checkPostQ()
% Attack: Attack Record
% Network_state: Network State Record
% Return value: Boolean
% Checks to see if any change is made to a network state
%  quality by the Attack.  If so, true is returned. Else false.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
checkPostQ(Attack,Network_state) -> 
  Network_state_Id = Network_state#networkstate.state_id,
  Attack_Id = Attack#attack.attack_id,

  Quality_pos = getAttPostQs(Attack),
% io:format("Quality_pos:-------~n~w~n-------~n",[Quality_pos]),
%BUILDING INSERT AND DELETE QUALITY POSTCONDITION LISTS
 Q_pos_insert_list = [[X,Y]||[insert,{quality,undefined,X,Y}] <- Quality_pos],
 Q_pos_delete_list = [[X,Y]||[delete,{quality,undefined,X,Y}] <- Quality_pos],

% io:format("Q INSERT LIST:-------~n~w~n-------~n",[Q_pos_insert_list]),
% io:format("Q DELETE LIST:-------~n~w~n-------~n",[Q_pos_delete_list]),

% GETTING NETWORK QUALITIES
  Qualities = getQualities(Network_state),
  Qs = ets:match(Qualities,{quality,Network_state_Id,'$1','$2'}),
% io:format("Qs :-------~n~w~n-------~n",[Qs]),

%TESTING FOR INSERTION NON-IDEMPOTENCY (true=non-idempotent => gens new state)
  Q_a_insert = sets:from_list(Q_pos_insert_list),
  Q_n = sets:from_list(Qs),
  Insert_result = not(sets:is_subset(Q_a_insert,Q_n)),

%TESTING FOR DELETION NON-IDEMPOTENCY (true=non-idempotent => gens new state)
  Q_a_delete = sets:from_list(Q_pos_delete_list),
  Delete_result = not(sets:is_disjoint(Q_a_delete,Q_n)),
  
% IF EITHER INSERTION OR DELETION CHANGES THE SYSTEM THEN NEW STATE
  Result = Insert_result orelse Delete_result,

% io:format("Q INS RES:~w ; DEL RES: ~w~n",[Insert_result, Delete_result]),
  Result.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% checkPostT()
% Attack: Attack Record
% Network_state: Network State Record
% Return value: Boolean
% Checks to see if any change is made to a network state
%  topology by the Attack.  If so, true is returned. Else false.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
checkPostT(Attack,Network_state) -> 
  Network_state_Id = Network_state#networkstate.state_id,
  Attack_Id = Attack#attack.attack_id,

  Topology_pos = getAttPostTs(Attack),
% io:format("Topology_pos:-------~n~w~n-------~n",[Topology_pos]),
%BUILDING INSERT AND DELETE TOPOLOGY POSTCONDITION LISTS
 T_pos_insert_list = [[X,Y]||[insert,{topology,Exploit_Id,X,Y}] <- Topology_pos],
 T_pos_delete_list = [[X,Y]||[delete,{topology,Exploit_Id,X,Y}] <- Topology_pos],

% io:format("INSERT LIST:-------~n~w~n-------~n",[T_pos_insert_list]),
% io:format("DELETE LIST:-------~n~w~n-------~n",[T_pos_delete_list]),

% GETTING NETWORK TOPOLOGIES
  Topologies = getTopologies(Network_state),
  Ts = ets:match(Topologies,{topology,Network_state_Id,'$1','$2'}),

%TESTING FOR INSERTION NON-IDEMPOTENCY (T=non-idempotent => gens new state)
  T_a_insert = sets:from_list(T_pos_insert_list),
  T_n = sets:from_list(Ts),
  Insert_result = not(sets:is_subset(T_a_insert,T_n)),

%TESTING FOR DELETION NON-IDEMPOTENCY (T=non-idempotent => gens new state)
  T_a_delete = sets:from_list(T_pos_delete_list),
  Delete_result = not(sets:is_disjoint(T_a_delete,T_n)),
  
% IF EITHER INSERTION OR DELETION CHANGES THE SYSTEM THEN NEW STATE
  Result = Insert_result orelse Delete_result,

% io:format("INS RES:~w ; DEL RES: ~w~n",[Insert_result, Delete_result]),
  Result.

%NEXT STATE FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%nextState(Attack Record, Network State Record) -> Network State Record
% Computes the next network state after an attack based on 
%  attack postconditions and current network state
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
nextState(Attack,Old_network_state) ->
    Attack_Id = Attack#attack.attack_id,
    State_Id = getNewId(),
    New_network_state = #networkstate{state_id=State_Id,
                        assets=updateA(getAssets(Old_network_state),
                          Old_network_state#networkstate.state_id,State_Id),
                        qualities=(updateQ(getAttPostQs(Attack),Attack_Id,
                             getQualities(Old_network_state),
                             Old_network_state#networkstate.state_id,
                             State_Id)),
                        topologies=(updateT(getAttPostTs(Attack),Attack_Id,
                              getTopologies(Old_network_state),
                              Old_network_state#networkstate.state_id,
                              State_Id))}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% getNewId () -> Triple tuple intended to be a unique ID
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
getNewId() -> erlang:now().

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% updateA(Assets Table, Old State ID, New State ID 
%          -> Assets Table 
% Copies assets from the old state to the new state
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
updateA(Assets_table,Old_state_Id,New_state_Id) ->
  Assets_list = lists:flatten(ets:match(Assets_table,{Old_state_Id,'$1'})),
  sets:from_list([{New_state_Id,X} || X <- Assets_list]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% updateQ(Oplist: List of Insert/Delete Ops,
%         Attack ID, Qualities Table, Old State ID,
%         New State ID 
%         ->
% New_qualities_table) 
%          -> Qualities table 
% Oplist is a table of  operations to perform to create a new table 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
updateQ(Oplist,Attack_Id,Qualities_table,Old_state_Id,New_state_Id) -> 
  Qualities_list = ets:match(Qualities_table,
                            {quality,Old_state_Id,'$1','$2'}),
  New_qualities = sets:from_list([{quality,New_state_Id,X,Y} || 
                       [X,Y] <- Qualities_list]),
  lists:foldl(fun(Op,Q_Acc) ->
                case Op of
                  [insert,{quality,undefined,X,Y}] -> 
                   New_entry = {quality,New_state_Id,X,Y},
                   sets:add_element(New_entry,Q_Acc);
                  [delete,{quality,undefined,X,Y}] -> 
                    sets:del_element({quality,New_state_Id,X,Y},Q_Acc)
                end
              end,
              New_qualities, Oplist).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% updateT(Oplist: ETS of Insert/Delete Ops,S: Old Table, TableName) 
%          -> ETS:New Table
% Oplist is a table of  operations to perform to create a new table 
% S is the Old Table
% TableName is the name of the new table
% T is the result -- the new table
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
updateT(Oplist,Attack_Id,Topologies_table,Old_state_Id,New_state_Id) -> 
  Topologies_list = ets:match(Topologies_table,
                            {topology,Old_state_Id,'$1','$2'}),
  New_topologies = sets:from_list([{topology,New_state_Id,X,Y} || 
                       [X,Y] <- Topologies_list]),
  lists:foldl(fun(Op,T_Acc) ->
                case Op of
                  [insert,{topology,undefined,X,Y}] ->
                    New_entry = {topology,New_state_Id,X,Y},
                    sets:add_element(New_entry,T_Acc);
                  [delete,{topology,undefined,X,Y}] ->
                    sets:del_element({topology,New_state_Id,X,Y},T_Acc)
                end
              end,
              New_topologies, Oplist).
