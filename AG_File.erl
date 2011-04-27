-module(AG_File).
-include("networkstate.hrl").
-include("exploitpattern.hrl").
-include("attack.hrl").
-export([loadNetworkModelFile/1,loadExploitsFile/1]).

% FILE FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% loadNetworkModelFile(F) ->
% F : String (file name)
% utility function to load network models from a .nm file
% creates a network state with all the associated tables
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
loadNetworkModelFile(F) ->
  {ok,[{Asset_list,Fact_list}]} = networkmodel_compiler:file(F),

  Assets_table = AG_Table_Management:newAssetsTable(),
  Qualities_table = AG_Table_Management:newQualitiesTable(qualities),
  Topologies_table = AG_Table_Management:newTopologiesTable(topologies),

  State_Id = getNewId(),
  lists:foreach(fun(Asset) -> ets:insert(Assets_table,[{State_Id,Asset}]) end,
                        Asset_list),

  lists:foreach(fun(Fact)-> 
    case Fact of
     {quality,A,P,V} -> Q = #quality{state_id=State_Id,asset_prop={A,P},
                                     value=V},
     ets:insert(Qualities_table,[Q]);
     {topology,A_1,A_2,R} -> T = #topology{state_id=State_Id, assets={A_1,A_2},
                                           relationship=R},
     ets:insert(Topologies_table,[T])
    end
  end, Fact_list),

  Network_state = #networkstate{state_id=State_Id,
                     assets=Assets_table,
                     qualities=Qualities_table,
                     topologies=Topologies_table},
  
  Network_state_table = AG_Table_Management:newNetworkStateTable(),
  ets:insert(Network_state_table,[Network_state]),
  {Network_state,Network_state_table,Assets_table,Qualities_table,
   Topologies_table}.
  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% loadExploitsFile(F) ->
% F : String (file name)
% utility function to load exploits from a .ep file
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
loadExploitsFile(F) ->
  {ok,[Exploit_list]} = exploit_compiler:file(F),
 io:format("Exploit_list:~n~w~n",[Exploit_list]),

  Exploit_table = AG_Table_Management:newExploitTable(),
%Create precondition tables
  Q_prc_table = AG_Table_Management:newQuality_prcTable(),
  T_prc_table = AG_Table_Management:newTopology_prcTable(),
%Create postcondition tables
  Q_poc_table = AG_Table_Management:newQuality_pocTable(),
  T_poc_table = AG_Table_Management:newTopology_pocTable(),

  lists:foreach(fun(E) -> AG_Table_Management:loadExploit(E,Exploit_table,Q_prc_table,T_prc_table,Q_poc_table,T_poc_table) end, Exploit_list),
  Exploit_table.
