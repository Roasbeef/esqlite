# esqlite_loom

This is Loom's maintained fork of [esqlite](https://github.com/mmzeeman/esqlite).
The Hex package is `esqlite_loom`; its OTP application remains `esqlite` and
its Erlang modules remain `esqlite3` and `esqlite3_nif`. Use one implementation
of those modules in a release.

Version 0.9.0 contains the private-query statement retirement fix submitted
in [upstream PR #105](https://github.com/mmzeeman/esqlite/pull/105), at commit
`45dbb48ce28c4d78b5cb93de0e1e78bb79f859d9`. Queries release the statements they
own before returning, so closing a connection does not wait for garbage
collection to retire those statements. Explicitly prepared statements keep
their existing ownership contract. The SQLite amalgamation is unchanged.

Rebar builds the native library from source. Install Erlang/OTP, Rebar3 and
a C compiler. Gleam consumers use the `sqlight_loom` package, which selects
this fork through Hex without requiring a patched Gleam compiler.

## Bounded observation queries

Version 0.9.1 adds `esqlite3:readonly_query/5` for a caller-owned `:memory:`
database. The caller loads a fixed schema and bounded data, then executes one
untrusted SELECT. SQLite parses and authorizes the query; the binding does not
maintain a second SQL parser. This API is intended for a separate sandboxed
Erlang VM. The connection handle and trusted loading phase must remain private.

Call `esqlite3:sandbox_heap_limit/0` before opening or loading observation
databases. It lowers SQLite's process-wide heap ceiling to 32 MiB and never
raises or restores that ceiling. The ceiling covers all SQLite connections in
this VM, including concurrent queries. Do not invoke this initializer in a
shared application VM whose databases require more memory.

```erlang
ok = esqlite3:sandbox_heap_limit(),
{ok, Connection} = esqlite3:open(":memory:"),
try
    ok = esqlite3:exec(Connection,
        "CREATE TABLE symbols(name TEXT, file TEXT);"
        "INSERT INTO symbols VALUES('collect','collector.gleam');"),
    {ok, {[<<"name">>], [[{text, <<"collect">>}]]}} =
        esqlite3:readonly_query(Connection,
            <<"SELECT name FROM symbols WHERE file = ?">>,
            [<<"collector.gleam">>], [<<"symbols">>],
            #{rows => 500, bytes => 1048576, milliseconds => 2000,
              operations => 1000000, columns => 32})
after
    ok = esqlite3:close(Connection)
end.
```

The table allowlist belongs to trusted application code. The query authorizer
permits SELECT, reads from those main-schema tables, and a fixed set of pure
functions. The connection must have no attached databases or temporary schema
objects. SQLite can omit the database name from the READ callback for
`COUNT(*)`; the main-only check prevents this callback from admitting another
schema with the same table name.

The function allowlist contains `count`, `sum`, `avg`, `min`, `max`, `total`,
`coalesce`, `ifnull`, `nullif`, `length`, `lower`, `upper`, `substr`, `substring`,
`trim`, `ltrim`, `rtrim`, `abs`, `round`, `instr`, `replace`, `typeof`, `unicode`,
`like`, and `glob`. Ordinary joins, grouping, ordering, nonrecursive common table
expressions, and parameterized predicates work. Recursive CTEs, writes, schema
changes, transactions, PRAGMAs, virtual tables, attachments, extension loading,
and filesystem functions fail authorization. System schema tables are not part
of the trusted allowlist.

`readonly_query/5` returns `{ok, {ColumnNames, Rows}}` or
`{error, {Kind, MessageBinary}}`. Names are UTF-8 binaries. Each cell preserves
its SQLite type as `null`, `{integer, Int64}`, `{real, Float}`, or
`{text, Utf8Binary}`. Parameters accept `null` or `undefined`, signed 64-bit
integers, floats, and UTF-8 text binaries. BLOB results and parameters are
rejected. Non-finite REAL values also fail, since Erlang floats cannot represent
SQLite infinity. Parameter count must match the prepared statement exactly.

Every key in the limits map is required. Callers can lower each budget, but
cannot exceed these ceilings:

| Budget | Ceiling |
| --- | ---: |
| Returned rows | 500 |
| Returned text/name bytes plus 16 bytes per cell | 1,048,576 |
| Prepare and execution deadline | 2,000 milliseconds |
| SQLite virtual machine instructions | 1,000,000 |
| Returned columns | 32 |

SQL is limited to 16 KiB, 64 parameters, and 128 KiB per value. SQLite also
limits expression depth, compound SELECTs, compiled instructions, function
arguments, wildcard patterns (128 bytes), and attachments. The progress handler checks instructions, elapsed
time, and caller death during preparation and stepping. Deadline and instruction
checks are cooperative; SQLite runs the callback every 100 instructions.
`esqlite3:interrupt/1` remains available to an independent cancellation owner.
The heap ceiling bounds SQLite allocations, while row and byte ceilings bound
the returned Erlang terms. They do not represent a heap limit for the entire VM.

SQLite prepares any trailing SQL under the same authorizer. A second statement
fails even when it is another SELECT or appears after comments and empty
semicolons. The authorizer remains installed through automatic reprepare and
statement retirement. Output limits return errors rather than truncated success.
Every path finalizes private statements and clears stack-owned callbacks before
returning. A connection has one exclusive owner; do not share it with concurrent
raw SQL, close, or schema-loading calls.

Use `esqlite3:finalize/1` to retire explicitly prepared loading statements,
including when binding or stepping fails. The statement must not be shared or
used after finalization. Existing `q/2` and `q/3` still own and finalize their
private statements automatically.

The bundled SQLite remains 3.50.4. Its build enables memory accounting and
progress callbacks, and restores the finite default expression-depth limit.
Those settings are necessary for the heap, instruction, and preparation bounds.
The initializer rejects incompatible builds. System SQLite builds are not the
validated distribution path for this API.

The enforcement follows SQLite's [security guidance](https://www.sqlite.org/security.html),
[authorizer contract](https://www.sqlite.org/c3ref/set_authorizer.html), and
[progress handler contract](https://www.sqlite.org/c3ref/progress_handler.html).
SQLite's [hard heap limit](https://www.sqlite.org/c3ref/hard_heap_limit64.html)
is process-wide, which is why its initialization belongs to the satellite VM.

Run `rebar3 eunit` for the existing database tests and actual native observation
queries. The suite exercises typed joins, empty-column COUNT reads, write and
filesystem denials, SQL tails, invalid parameters, bounded output, time and
instruction exhaustion, heap exhaustion, interrupt, caller death, and error
cleanup followed by connection reuse.

The original esqlite documentation follows.

---

Esqlite ![Test](https://github.com/mmzeeman/esqlite/workflows/Test/badge.svg)
=======

An Erlang nif library for sqlite3.

Introduction
------------

This library allows you to use the excellent sqlite engine from
erlang. The library is implemented as a nif library, which allows for
the fastest access to a sqlite database. This can be risky, as a bug
in the nif library or the sqlite database can crash the entire Erlang
VM. If you do not want to take this risk, it is always possible to
access the sqlite nif from a separate erlang node.

Special care has been taken not to block the normal erlang scheduler
of the calling process. This is done by handling neccesary commands
from erlang by using a dirty scheduler.

SQLite Compile Options
----------------------

Esqlite contains an embedded version of sqlite3. Currently version
`3.50.4` is embedded in the repository. It is also possible to use
sqlite provided by the system by using the `ESQLITE_USE_SYSTEM` 
environment flag. 

When sqlite is compiled, the following compile flags are used. These
flags are recommended by sqlite.

```
SQLITE_DQS=0 SQLITE_THREADSAFE=1 SQLITE_DEFAULT_MEMSTATUS=1
SQLITE_DEFAULT_WAL_SYNCHRONOUS=1 SQLITE_LIKE_DOESNT_MATCH_BLOBS
SQLITE_MAX_EXPR_DEPTH=1000 SQLITE_OMIT_DEPRECATED
SQLITE_USE_ALLOCA
SQLITE_OMIT_AUTOINIT SQLITE_USE_URI
SQLITE_ENABLE_FTS3 SQLITE_ENABLE_FTS3_PARENTHESIS
SQLITE_ENABLE_FTS4
SQLITE_ENABLE_FTS5
SQLITE_ENABLE_MATH_FUNCTIONS
SQLITE_ENABLE_JSON1
SQLITE_ENABLE_RTREE
SQLITE_ENABLE_GEOPOLY
```

The use of flag `SQLITE_DQS=0` is new in version `0.7`. It can lead
to incompatibilities with respect to the use of single and double 
qouted values. Historically sqlite didn't differentiate between double
and single quoted values, but SQL does. In retrospect, the authors of 
sqlite, think this was a mistake, and introduced this compile flag 
to correct this mistake. It means that string literals **must** use 
single quotes:

```
INSERT INTO table VALUES('abcd', 1234);
```

When double quotes are used the value is seen as object values in 
SQL. So a query like:

```
INSERT INTO table VALUES("abcd", 1234);
```

Will not work, because it sees the value 'abcd' as a SQL object
value, and not a string literal.

Version 0.8.0
-------------

This version is a major derivation from previous versions. When 
I started with this library it was implemented by using a separate
os level thread per connection. At the time this was the only way
to use functions in C which take longer to process than 1ms. 
A lot has changed since then. The VM now has dirty schedulers 
which make it possible to remove the thread per connection.
This makes it possible to open a lot more connections. On the
SQLite side some things have also changed. Extended error codes,
introspection into the internals. This release modernizes the
integration. In some places the API is no longer compatible and
will require small changes. In order to ease this process the 
library now has typespecs, and the documentation was extended.


