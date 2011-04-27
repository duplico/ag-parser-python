-module(AG_Table_Management).
-include("networkstate.hrl").
-include("exploitpattern.hrl").
-include("attack.hrl").
-export([installNetworkState/5,findNetworkState/2,exploitListfromTable/1,loadExploit/2,deleteAttackElements/1,
newAssetsTable/0,newQualitiesTable/1,newTopologiesTable/1,newNetworkStateTable/0,newTableVertexIndex/0,
newQuality_prsTable/0,newTopology_prsTable/0,newQuality_posTable/0,newTopology_posTable/0,
newQuality_prcTable/0,newTopology_prcTable/0,newQuality_pocTable/0,newTopology_pocTable/0,
newExploitTable/0,newAttackTable/0,removeDeadAttacks/1]).

% TABLE MANAGEMENT FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% installNetworkState()
% Network_state_table
% Network State Record
% Return value: Network state
% inserts the new network state into Network_state_table
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
installNetworkState(Network_state_table,#networkstate{state_id=State_id,
   assets=Assets,qualities=Qualities,topologies=Topologies},
   Assets_table,Qualities_table,Topologies_table) -> 
   ets:insert(Assets_table,sets:to_list(Assets)),
   ets:insert(Qualities_table,sets:to_list(Qualities)),
   ets:insert(Topologies_table,sets:to_list(Topologies)),
  N = #networkstate{state_id=State_id,assets=Assets_table,
                    qualities=Qualities_table,topologies=Topologies_table},
  ets:insert(Network_state_table,N),
  N.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% findNetworkState(N,Network_state_table)
%  N: Network state
%  Network_state_table: ets Network state table
%  Return value: #networkstate.state_id OR false
%  Compares network state N against every state in the
%   table Network_state_table to see if a match exists
%  Comparison uses equalsNetworkState which
%   compares assets, qualities and topologies 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
findNetworkState(N,Network_state_table) ->
  ets:foldl(fun(X,N_acc) -> case equalsNetworkStateTmp(N,X) of
                           true -> X#networkstate.state_id;
                           false -> N_acc
                      end
                    end, false, Network_state_table).
                    

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% exploitListfromTable()
% Exploit_table: ets Table of ExploitPatterns
% Return value: A List of Exploit Patterns
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
exploitListfromTable(Exploit_table) ->
  [X || [X] <- ets:match(Exploit_table,'$1')]
.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% loadExploit(E,Exploit_table) ->
% E : Tuple (format: {Exploit_name,Parameter List,Precondition List,
%                     Postcondition List})
% utility function to load an exploit from the intermediate
%  data structure produced by exploit_compiler
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
loadExploit(E,Exploit_table,Q_prc_table,T_prc_table,Q_poc_table,T_poc_table) ->
 {Exploit_name,Param_list,Precondition_list,Postcondition_list} = E,

  Exploit_Id = getNewId(),
%Create precondition tables
% Q_prc_table = newQuality_prcTable(),
% T_prc_table = newTopology_prcTable(),

%Populate precondition tables
  lists:foreach(fun(Precond)-> 
    case Precond of
     {quality,A_v,P,V} -> Q_e = #quality_e{exploit_id=Exploit_Id,asset_var_prop={A_v,P},value=V},
                          ets:insert(Q_prc_table,[Q_e]);
     {topology,A_1,A_2,R} -> T_e = #topology_e{exploit_id=Exploit_Id,asset_vars={A_1,A_2},relationship=R},
                          ets:insert(T_prc_table,[T_e]) 
    end
  end, Precondition_list),

%Create postcondition tables
% Q_poc_table = newQuality_pocTable(),
% T_poc_table = newTopology_pocTable(),

%Populate postcondition tables
  lists:foreach(fun(Postcond)-> 
    case Postcond of
     {Op,{quality,A_v,P,V}} -> Q_e = #quality_e{exploit_id=Exploit_Id,asset_var_prop={A_v,P},value=V},
                          ets:insert(Q_poc_table,[{Op,Q_e}]);
     {Op,{topology,A_1,A_2,R}} -> T_e = #topology_e{exploit_id=Exploit_Id,asset_vars={A_1,A_2},
                                                    relationship=R},
                          ets:insert(T_poc_table,[{Op,T_e}]) 
    end
  end, Postcondition_list),

  EP = #exploitpattern{exploit_id=Exploit_Id,vulnerability=Exploit_name,parameters=Param_list,
                        quality_prc=Q_prc_table,
                        topology_prc=T_prc_table,
                        quality_poc=Q_poc_table,
                        topology_poc=T_poc_table},
  
  ets:insert(Exploit_table,[EP]).

%TABLE CONSTRUCTION/DESTRUCTION FUNCTIONS

newAssetsTable() -> ets:new(asset_table,[bag,{keypos,1}]). 

newQualitiesTable(Table_name) -> ets:new(Table_name,[bag,{keypos,2}]). 

newTopologiesTable(Table_name) -> ets:new(Table_name,[bag,{keypos,2}]). 

newNetworkStateTable() -> ets:new(networkstate_table,[{keypos,#networkstate.state_id}]).

newTableVertexIndex() -> ets:new(table_vertex_index,[{keypos,1}]).

newQuality_prsTable() -> ets:new(q_prs_table,[bag,{keypos,1}]).

newTopology_prsTable() -> ets:new(t_prs_table,[bag,{keypos,1}]).

newQuality_posTable() -> ets:new(q_pos__table,[bag,{keypos,1}]).

newTopology_posTable() -> ets:new(t_pos_table,[bag,{keypos,1}]).

%newQuality_prcTable() -> ets:new(q_prc_table,[bag,{keypos,#quality_e.asset_var_prop}]).
newQuality_prcTable() -> ets:new(q_prc_table,[bag,{keypos,2}]).

%newTopology_prcTable() -> ets:new(t_prc_table,[bag,{keypos,#topology_e.asset_vars}]).
newTopology_prcTable() -> ets:new(t_prc_table,[bag,{keypos,2}]).

newQuality_pocTable() -> ets:new(q_poc__table,[bag,{keypos,2}]).

newTopology_pocTable() -> ets:new(t_poc_table,[bag,{keypos,2}]).

%newExploitTable() -> ets:new(exploit_table,[{keypos,#exploitpattern.vulnerability}]).
newExploitTable() -> ets:new(exploit_table,[bag,{keypos,2}]).

newAttackTable() -> ets:new(attack_table,[{keypos,#attack.attack_id}]). 

removeDeadAttacks(AL) -> 
  lists:foreach(fun(A) -> deleteAttackElements(A) end,AL).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% deleteAttackElements()
% #attack.*:  Attack Record
% Deletes attack record elements from the Attack tables
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
deleteAttackElements(#attack{attack_id=Attack_Id,vulnerability=Vulnerability,quality_prs=Quality_prs,topology_prs=Topology_prs,quality_pos=Quality_pos,topology_pos=Topology_pos}) ->
            ets:delete(Quality_prs,Attack_Id),
            ets:delete(Topology_prs,Attack_Id),
            ets:delete(Quality_pos,Attack_Id),
            ets:delete(Topology_pos,Attack_Id).
