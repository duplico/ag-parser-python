-module(ag_main).
-include("networkstate.hrl").
-include("exploitpattern.hrl").
-include("attack.hrl").
-export([start/0]).

start() -> 

%INITIALIZE NETWORK STATE
 
NM_line = io:get_line("Network Model File >"),
NM_filename = string:left(NM_line,string:len(NM_line)-1),
networkmodel_compiler:make(),
{N,Network_state_table,Assets_table,Qualities_table,Topologies_table} =
  ag_file:loadNetworkModelFile(NM_filename),

%INITIALIZE  THE ATTACK GRAPH
Attack_graph = digraph:new(),
V = digraph:add_vertex(Attack_graph,N),
Table_vertex_index = ag_table_management:newTableVertexIndex(),
ets:insert(Table_vertex_index,{N#networkstate.state_id,V}),

tv:start(),

%INITIALIZE EXPLOITS TABLES
EP_line = io:get_line("Exploits File >"),
EP_filename = string:left(EP_line,string:len(EP_line)-1),
exploit_compiler:make(),
Exploit_table = ag_file:loadExploitsFile(EP_filename),
EL = ag_table_management:exploitListfromTable(Exploit_table),
  io:format("EL:-------~n~w~n--------~n",[EL]),

%GET THE DEPTH OF THE ATTACK GRAPH TO GENERATE
Depth_line = io:get_line("Depth >"),
{Depth,Rest} = string:to_integer(Depth_line),

%GET THE NAME OF THE OUTPUT FILE NAME 
Output_line = io:get_line("Output File >"),
Output_filename = string:left(Output_line,string:len(Output_line)-1),

%INITIALIZE ATTACK TABLES
Attack_table = ag_table_management:newAttackTable(),
Q_prs = ag_table_management:newQuality_prsTable(),
T_prs = ag_table_management:newTopology_prsTable(),
Q_pos = ag_table_management:newQuality_posTable(),
T_pos = ag_table_management:newTopology_posTable(),

%COMPUTE THE ATTACK GRAPH
ag_generation:buildAttackGraph(EL,[N],Network_state_table,Assets_table,Qualities_table,
                 Topologies_table,Attack_table,Q_prs,T_prs,Q_pos,T_pos,
                 Attack_graph,Table_vertex_index,Depth),

%TRANSFORM THE DIGRAPH TO GRAPHVIZ FORMAT
ag_output:digraphToDot(Attack_graph,Output_filename).
