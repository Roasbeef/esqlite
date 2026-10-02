%% Real native SQLite coverage: the parser, authorizer, preparation tail and
%% progress callbacks participate in every query below. No routing fake can
%% stand in for the security boundary that the satellite will invoke.
-module(readonly_query_test).
-include_lib("eunit/include/eunit.hrl").

limits() -> #{rows => 500, bytes => 1048576, milliseconds => 2000,
              operations => 1000000, columns => 32}.

query(C, Sql) -> query(C, Sql, [], limits()).
query(C, Sql, Params, Limits) ->
    esqlite3:readonly_query(C, Sql, Params, [<<"symbols">>, <<"refs">>], Limits).

with_db(Test) ->
    ok = esqlite3:sandbox_heap_limit(),
    {ok, C} = esqlite3:open(":memory:"),
    try
        ok = esqlite3:exec(C,
            "CREATE TABLE symbols(id INTEGER, name TEXT);"
            "CREATE TABLE refs(symbol_id INTEGER, file TEXT);"
            "INSERT INTO symbols VALUES(1,'alpha'),(2,'beta');"
            "INSERT INTO refs VALUES(1,'a.gleam'),(1,'b.gleam'),(2,'b.gleam');"),
        Test(C)
    after
        ok = esqlite3:close(C)
    end.

typed_join_test() -> with_db(fun(C) ->
    ?assertEqual({ok, {[<<"name">>, <<"files">>],
        [[{text, <<"alpha">>}, {integer, 2}]]}},
        query(C, <<"SELECT s.name, COUNT(DISTINCT r.file) AS files "
            "FROM symbols s JOIN refs r ON r.symbol_id=s.id "
            "GROUP BY s.id HAVING files > ? ORDER BY s.name; -- tail\n">>,
            [1], limits())),
    ?assertEqual({ok, {[<<"NULL">>, <<"?">>, <<"?">>, <<"?">>],
        [[null, {integer, 9223372036854775807}, {real, 1.5}, {text, <<"λ"/utf8>>}]]}},
        query(C, <<"SELECT NULL, ?, ?, ?">>,
              [9223372036854775807, 1.5, <<"λ"/utf8>>], limits())),

    %% COUNT(*) reads a table with an empty authorizer column name.
    ?assertMatch({ok, {_, [[{integer, 3}]]}}, query(C, <<"SELECT COUNT(*) FROM refs">>))
end).

denied_routes_test() -> with_db(fun(C) ->
    Queries = [
        <<"DELETE FROM symbols">>, <<"UPDATE symbols SET name='oops'">>,
        <<"INSERT INTO symbols VALUES(3,'oops')">>, <<"DROP TABLE symbols">>,
        <<"CREATE TABLE x(id)">>, <<"CREATE VIRTUAL TABLE x USING fts5(v)">>,
        <<"ATTACH ':memory:' AS x">>, <<"DETACH main">>,
        <<"PRAGMA query_only=OFF">>, <<"PRAGMA database_list">>,
        <<"SELECT * FROM pragma_database_list">>, <<"SELECT * FROM sqlite_master">>,
        <<"SELECT load_extension('/tmp/evil')">>, <<"SELECT readfile('/etc/passwd')">>,
        <<"SELECT writefile('/tmp/evil','oops')">>, <<"BEGIN">>, <<"VACUUM INTO '/tmp/evil'">>,
        <<"WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x) SELECT n FROM x">>
    ],
    lists:foreach(fun(Sql) ->
        ?assertMatch({error, {_Kind, _Message}}, query(C, Sql))
    end, Queries),
    ?assertMatch({ok, {_, [[{integer, 2}]]}}, query(C, <<"SELECT COUNT(*) FROM symbols">>))
end).

tail_and_parameters_test() -> with_db(fun(C) ->
    ?assertMatch({error, {multiple_statements, _}}, query(C, <<"SELECT 1; SELECT 2">>)),
    ?assertMatch({error, {multiple_statements, _}}, query(C, <<"SELECT 1;;SELECT 2">>)),
    ?assertMatch({error, {multiple_statements, _}}, query(C, <<"SELECT 1;-- comment\n;SELECT 2">>)),
    ?assertMatch({ok, {_, [[{integer, 1}]]}}, query(C, <<"SELECT 1; ;-- comment\n;">>)),
    ?assertMatch({error, {read_only_denied, _}}, query(C, <<"SELECT 1; DELETE FROM refs">>)),
    ?assertMatch({error, {invalid_argument, _}}, query(C, <<"SELECT ?">>, [], limits())),
    ?assertMatch({error, {invalid_argument, _}}, query(C, <<"SELECT ?">>, [1, 2], limits())),
    ?assertMatch({error, {invalid_argument, _}}, query(C, <<"SELECT ?">>, [{blob, <<1>>}], limits())),
    ?assertMatch({error, {invalid_argument, _}}, query(C, <<"SELECT ?">>, [<<255>>], limits())),
    ?assertMatch({error, {invalid_argument, _}}, query(C, <<"SELECT 1", 0, "; DELETE FROM refs">>)),
    ?assertMatch({ok, {_, [[{integer, 1}]]}}, query(C, <<"SELECT 'alpha' LIKE 'a%'">>)),
    ?assertMatch({error, {sql_error, _}}, query(C, <<"SELECT 'alpha' LIKE ?">>,
        [binary:copy(<<"a">>, 129)], limits())),
    ?assertMatch({error, {non_finite_real, _}}, query(C, <<"SELECT 1e999">>)),
    ?assertMatch({error, {non_finite_real, _}}, query(C, <<"SELECT 1e308 * 1e308">>)),
    ?assertMatch({error, {blob_not_supported, _}}, query(C, <<"SELECT X'01'">>)),
    ?assertMatch({error, {invalid_text, _}}, query(C, <<"SELECT CAST(X'FF' AS TEXT)">>))
end).

budgets_and_retirement_test() -> with_db(fun(C) ->
    ?assertMatch({error, {row_limit, _}}, query(C,
        <<"SELECT file FROM refs ORDER BY file">>, [], (limits())#{rows => 2})),
    ?assertMatch({error, {column_limit, _}}, query(C,
        <<"SELECT 1,2">>, [], (limits())#{columns => 1})),
    ?assertMatch({error, {byte_limit, _}}, query(C,
        <<"SELECT name FROM symbols">>, [], (limits())#{bytes => 1})),
    ?assertMatch({error, {instruction_limit, _}}, query(C,
        <<"SELECT count(*) FROM refs a,refs b,refs c,refs d,refs e,refs f,refs g,refs h">>,
        [], (limits())#{operations => 100})),
    ?assertMatch({error, {timeout, _}}, query(C,
        <<"SELECT count(*) FROM refs a,refs b,refs c,refs d,refs e,refs f,refs g,refs h,refs i,refs j,refs k,refs l">>,
        [], (limits())#{milliseconds => 1})),

    %% Each failed query must finalize its statement and clear the callback's
    %% stack pointer before this subsequent query reuses the same connection.
    ?assertMatch({ok, {_, [[{integer, 2}]]}}, query(C, <<"SELECT count(*) FROM symbols">>))
end).

file_database_refused_test() ->
    Path = filename:join("test/dbs", "readonly-query.db"),
    ok = filelib:ensure_dir(Path),
    {ok, C} = esqlite3:open(Path),
    try
        ?assertMatch({error, {invalid_argument, _}}, query(C, <<"SELECT 1">>))
    after
        ok = esqlite3:close(C),
        file:delete(Path)
    end.

ceiling_arguments_test() -> with_db(fun(C) ->
    lists:foreach(fun({Key, Value}) ->
        ?assertMatch({error, {invalid_argument, _}},
            query(C, <<"SELECT 1">>, [], (limits())#{Key => Value}))
    end, [{rows, 501}, {bytes, 1048577}, {milliseconds, 2001},
          {operations, 1000001}, {columns, 33}, {rows, 0}]),
    ?assertMatch({error, {invalid_argument, _}}, query(C,
        binary:copy(<<" ">>, 16385))),
    ?assertMatch({error, {invalid_argument, _}}, query(C, <<"SELECT ?">>,
        [binary:copy(<<"a">>, 131073)], limits()))
end).

execution_error_retirement_test() -> with_db(fun(C) ->
    ?assertEqual({error, {sql_error, <<"integer overflow">>}},
        query(C, <<"SELECT sum(9223372036854775807) FROM refs">>)),
    ?assertMatch({ok, {_, [[{integer, 3}]]}}, query(C, <<"SELECT count(*) FROM refs">>))
end).

trusted_schema_restriction_test() ->
    lists:foreach(fun(Setup) ->
        with_db(fun(C) ->
            ok = esqlite3:exec(C, Setup),
            ?assertMatch({error, {read_only_denied, _}},
                query(C, <<"SELECT count(*) FROM refs">>))
        end)
    end, ["ATTACH ':memory:' AS other", "CREATE TEMP TABLE refs(x)"]).

native_heap_exhaustion_test() -> with_db(fun(C) ->
    {ok, Statement} = esqlite3:prepare(C, "INSERT INTO refs VALUES(1,?)"),
    try
        lists:foreach(fun(_) ->
            ok = esqlite3:bind(Statement, [binary:copy(<<"a">>, 2048)]),
            '$done' = esqlite3:step(Statement),
            ok = esqlite3:reset(Statement)
        end, lists:seq(1, 200))
    after
        ok = esqlite3:finalize(Statement)
    end,

    %% Sorting the Cartesian product requires more than the fixed 32 MiB
    %% ceiling. The seeded database itself uses less than one MiB.
    ?assertMatch({error, {memory_limit, _}}, query(C,
        <<"SELECT a.file || b.file AS combined FROM refs a,refs b ORDER BY combined">>)),
    #{used := Used} = esqlite3_nif:memory_stats(0),
    ?assert(Used =< 32 * 1024 * 1024),
    ?assertMatch({ok, {_, [[{integer, 203}]]}}, query(C, <<"SELECT count(*) FROM refs">>))
end).

interrupt_test() -> with_db(fun(C) ->
    %% The high-cardinality SELECT cannot finish before its execution ceiling.
    %% An independent caller interrupts it through SQLite's supported API.
    Parent = self(),
    Worker = spawn(fun() ->
        Parent ! query_started,
        Parent ! {query_result, query(C,
            <<"SELECT count(*) FROM refs a,refs b,refs c,refs d,refs e,refs f,refs g,refs h,refs i,refs j,refs k,refs l">>)}
    end),
    receive query_started -> ok end,
    timer:sleep(1),
    ok = esqlite3:interrupt(C),
    receive
        {query_result, Result} -> ?assertMatch({error, {cancelled, _}}, Result)
    after 3000 -> exit(Worker, kill), ?assert(false)
    end,
    ?assertMatch({ok, {_, [[{integer, 3}]]}}, query(C, <<"SELECT count(*) FROM refs">>))
end).

caller_death_retirement_test() -> with_db(fun(C) ->
    Parent = self(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Parent ! query_started,
        query(C, <<"SELECT count(*) FROM refs a,refs b,refs c,refs d,refs e,refs f,refs g,refs h,refs i,refs j,refs k,refs l">>)
    end),
    receive query_started -> ok end,
    timer:sleep(1),
    exit(Worker, kill),
    receive
        {'DOWN', Monitor, process, Worker, killed} -> ok
    after 3000 -> ?assert(false)
    end,

    %% Process death must not leave an authorizer holding the dead NIF stack.
    ?assertMatch({ok, {_, [[{integer, 3}]]}}, query(C, <<"SELECT count(*) FROM refs">>))
end).
