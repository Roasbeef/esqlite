%% The satellite flattens compiled modules and the one trusted native library.
%% A fresh VM must load that artifact without an OTP app directory or cwd priv.
-module(native_loader_test).
-include_lib("eunit/include/eunit.hrl").

flat_artifact_loader_test() ->
    Root = filename:join("/tmp", "flat-sqlite-" ++
        integer_to_list(erlang:unique_integer([positive, monotonic]))),
    Flat = filename:join(Root, "ebin"),
    Cwd = filename:join(Root, "unrelated-cwd"),
    ok = filelib:ensure_dir(filename:join(Flat, "placeholder")),
    ok = file:make_dir(Cwd),
    try
        lists:foreach(fun(Module) ->
            {ok, _} = file:copy(code:which(Module),
                filename:join(Flat, atom_to_list(Module) ++ ".beam"))
        end, [esqlite3, esqlite3_nif]),
        {ok, _} = file:copy(filename:join(code:priv_dir(esqlite), "esqlite3_nif.so"),
            filename:join(Flat, "esqlite3_nif.so")),
        Eval = "case code:ensure_loaded(esqlite3_nif) of {module,_}->ok;"
            "Error->io:format(\"native load failed: ~p path=~p app=~p~n\","
            "[Error,code:which(esqlite3_nif),code:priv_dir(esqlite)]),halt(1) end,"
            "ok=esqlite3:sandbox_heap_limit(),{ok,D}=esqlite3:open(\":memory:\"),"
            "{ok,{[<<\"7\">>],[[{integer,7}]]}}=esqlite3:readonly_query(D,<<\"SELECT 7\">>,[],[],"
            "#{rows=>500,bytes=>1048576,milliseconds=>2000,operations=>1000000,columns=>32}),"
            "ok=esqlite3:close(D),halt(0).",
        Port = open_port({spawn_executable, os:find_executable("erl")},
            [binary, exit_status, stderr_to_stdout, {cd, Cwd},
             {args, ["-noshell", "-pa", filename:absname(Flat), "-eval", Eval]}]),
        ?assertEqual({0, <<>>}, collect(Port, <<>>))
    after
        ok = file:del_dir_r(Root)
    end.

collect(Port, Output) ->
    receive
        {Port, {data, Data}} -> collect(Port, <<Output/binary, Data/binary>>);
        {Port, {exit_status, Status}} -> {Status, Output}
    after 4000 ->
        port_close(Port),
        error(native_loader_timeout)
    end.
