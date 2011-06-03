-module(networkmodel_compiler).

-export([make/0, file/1]).

%% usage 
%%    networkmodel_compiler:file(File)
%%        Converts File.ebnf -> File.xbin
%%    networkmodel_compiler:make()
%%        Makes the parser

make() ->
    %% The compiler is made from
    %% networkmodelparser.yrl and networkmodellexer.xrl
    yecc:file(networkmodelparser),
    c:c(networkmodelparser),
    leex:file(networkmodellexer),
    c:c(networkmodellexer).

file(F) ->
    io:format("Parsing ~s.nm~n", [F]),
    {ok, Stream} = file:open(F ++ ".nm", read),
    Parse = handle(Stream, 1, [], 0),
    file:close(Stream),
    Parse.

handle(Stream, LineNo, L, NErrors) ->
    handle1(io:requests(Stream, [{get_until,foo,networkmodellexer,
			  tokens,[LineNo]}]), Stream, L, NErrors).

handle1({ok, Toks, Next}, Stream, L, Nerrs) ->
    case networkmodelparser:parse(Toks) of
	{ok, Parse} ->
	    handle(Stream, Next, [Parse|L], Nerrs);
	{error, {Line, Mod, What}} ->
	    Str = apply(Mod, format_error, [What]),
	    io:format("** ~w ~s~n", [Line, Str]),
	    handle(Stream, Next, L, Nerrs+1);
	Other ->
	    io:format("Bad_parse:~p\n", [Other]),
	    handle(Stream, Next, L, Nerrs+1)
    end;
handle1({eof, _}, Stream, L, 0) ->
    {ok, lists:reverse(L)};
handle1({eof, _}, Stream, L, N) ->
    {error, N};
handle1(What, Stream, L, Nerrs) ->
    io:format("Here:~p\n", [What]),
    handle(Stream, 1, L, Nerrs+1).

first([H]) -> [];
first([H|T]) -> [H|first(T)];
first([]) -> [].

