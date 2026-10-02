/* One bounded observation query. Connections belong exclusively to the caller;
 * neither their handles nor their trusted schema-loading phase may escape to
 * untrusted code. SQLite remains the only SQL parser and policy interpreter. */
#define RO_SQL_BYTES 16384
#define RO_PARAMS 64
#define RO_VALUE_BYTES 131072
#define RO_HEAP_BYTES (32 * 1024 * 1024)
#define RO_PROGRESS_INTERVAL 100

static ErlNifMutex *readonly_heap_mutex;

typedef struct {
    ErlNifEnv *env;
    ErlNifBinary tables[32];
    unsigned table_count;
    unsigned operations;
    unsigned max_operations;
    ErlNifTime deadline;
    const char *failure;
} readonly_context;

static ERL_NIF_TERM
readonly_error(ErlNifEnv *env, const char *kind, const char *message)
{
    size_t bytes = strlen(message);
    if(bytes > 1024) {
        bytes = 1024;

        /* Preserve a UTF-8 boundary when SQLite names a long Unicode token. */
        while(bytes && (((unsigned char)message[bytes] & 0xc0) == 0x80)) bytes--;
    }
    return enif_make_tuple2(env, make_atom(env, "error"),
        enif_make_tuple2(env, make_atom(env, kind), make_binary(env, message, bytes)));
}

/* Reject invalid UTF-8 rather than passing binaries off as Gleam strings. */
static int
readonly_utf8(const unsigned char *p, size_t length)
{
    for(size_t i = 0; i < length;) {
        unsigned c = p[i++], n, value, minimum;
        if(c < 0x80) continue;
        if(c >= 0xc2 && c <= 0xdf) { n = 1; value = c & 31; minimum = 0x80; }
        else if(c >= 0xe0 && c <= 0xef) { n = 2; value = c & 15; minimum = 0x800; }
        else if(c >= 0xf0 && c <= 0xf4) { n = 3; value = c & 7; minimum = 0x10000; }
        else return 0;
        if(n > length - i) return 0;
        while(n--) {
            c = p[i++];
            if((c & 0xc0) != 0x80) return 0;
            value = (value << 6) | (c & 63);
        }
        if(value < minimum || value > 0x10ffff ||
           (value >= 0xd800 && value <= 0xdfff)) return 0;
    }
    return 1;
}

static int
readonly_check(readonly_context *context)
{
    if(!enif_is_current_process_alive(context->env)) context->failure = "cancelled";
    else if(enif_monotonic_time(ERL_NIF_MSEC) >= context->deadline)
        context->failure = "timeout";
    return context->failure != NULL;
}

/* The handler also runs during prepare on the bundled SQLite version. */
static int
readonly_progress(void *arg)
{
    readonly_context *context = arg;
    context->operations += RO_PROGRESS_INTERVAL;
    if(context->operations >= context->max_operations)
        context->failure = "instruction_limit";
    return readonly_check(context);
}

static int
readonly_authorizer(void *arg, int action, const char *first,
                    const char *second, const char *database, const char *source)
{
    readonly_context *context = arg;
    (void)source;
    if(action == SQLITE_SELECT) return SQLITE_OK;
    if(action == SQLITE_READ && first &&
       ((database && !strcmp(database, "main")) ||
        (!database && second && !*second))) {
        for(unsigned i = 0; i < context->table_count; i++) {
            if(strlen(first) == context->tables[i].size &&
               !memcmp(first, context->tables[i].data, context->tables[i].size))
                return SQLITE_OK;
        }
    }
    if(action == SQLITE_FUNCTION && second) {
        static const char *functions[] = {
            "count", "sum", "avg", "min", "max", "total", "coalesce", "ifnull",
            "nullif", "length", "lower", "upper", "substr", "substring", "trim",
            "ltrim", "rtrim", "abs", "round", "instr", "replace", "typeof", "unicode", "like", "glob"
        };
        for(unsigned i = 0; i < sizeof(functions) / sizeof(functions[0]); i++)
            if(!sqlite3_stricmp(second, functions[i])) return SQLITE_OK;
    }
    context->failure = "read_only_denied";
    return SQLITE_DENY;
}

/* This process-global ceiling is lowered once by the satellite before loading
 * any snapshot. It is never restored or raised by another concurrent query. */
static ERL_NIF_TERM
esqlite_sandbox_heap_limit(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argv;
    if(argc != 0) return enif_make_badarg(env);
    if(sqlite3_libversion_number() < 3041000 ||
       sqlite3_compileoption_used("DEFAULT_MEMSTATUS=0") ||
       sqlite3_compileoption_used("OMIT_PROGRESS_CALLBACK") ||
       sqlite3_compileoption_used("MAX_EXPR_DEPTH=0"))
        return readonly_error(env, "unsupported_build", "SQLite hardening flags are missing");
    enif_mutex_lock(readonly_heap_mutex);
    sqlite3_int64 current = sqlite3_hard_heap_limit64(-1);
    if(current <= 0 || current > RO_HEAP_BYTES)
        sqlite3_hard_heap_limit64(RO_HEAP_BYTES);
    current = sqlite3_hard_heap_limit64(-1);
    enif_mutex_unlock(readonly_heap_mutex);
    if(current <= 0 || current > RO_HEAP_BYTES)
        return readonly_error(env, "unsupported_build", "SQLite heap ceiling is unavailable");
    return make_atom(env, "ok");
}

static int
readonly_limit(ErlNifEnv *env, ERL_NIF_TERM map, const char *key,
               unsigned ceiling, unsigned *value)
{
    ERL_NIF_TERM term;
    return enif_get_map_value(env, map, make_atom(env, key), &term) &&
           enif_get_uint(env, term, value) && *value > 0 && *value <= ceiling;
}

static int
readonly_bind(ErlNifEnv *env, sqlite3_stmt *statement, ERL_NIF_TERM params)
{
    ERL_NIF_TERM head, tail = params;
    unsigned count;
    if(!enif_get_list_length(env, params, &count) || count > RO_PARAMS ||
       count != (unsigned)sqlite3_bind_parameter_count(statement)) return SQLITE_MISUSE;
    for(unsigned i = 1; i <= count; i++) {
        ErlNifSInt64 integer;
        double real;
        ErlNifBinary text;
        int rc;
        if(!enif_get_list_cell(env, tail, &head, &tail)) return SQLITE_MISUSE;
        if(enif_is_identical(head, make_atom(env, "null")) ||
           enif_is_identical(head, make_atom(env, "undefined")))
            rc = sqlite3_bind_null(statement, i);
        else if(enif_get_int64(env, head, &integer))
            rc = sqlite3_bind_int64(statement, i, integer);
        else if(enif_get_double(env, head, &real) && isfinite(real))
            rc = sqlite3_bind_double(statement, i, real);
        else if(enif_inspect_binary(env, head, &text) && text.size <= RO_VALUE_BYTES &&
                readonly_utf8(text.data, text.size))
            rc = sqlite3_bind_text(statement, i, (const char *)text.data,
                                  text.size, SQLITE_TRANSIENT);
        else return SQLITE_MISUSE;
        if(rc != SQLITE_OK) return rc;
    }
    return SQLITE_OK;
}

static ERL_NIF_TERM
esqlite_readonly_query(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    esqlite3 *connection;
    ErlNifBinary sql;
    unsigned max_rows, max_bytes, milliseconds, max_columns, count;
    readonly_context context = {.env = env};
    if(argc != 5 || !enif_get_resource(env, argv[0], esqlite3_type, (void **)&connection) ||
       !enif_inspect_binary(env, argv[1], &sql) || sql.size == 0 ||
       sql.size > RO_SQL_BYTES || memchr(sql.data, 0, sql.size) ||
       !readonly_utf8(sql.data, sql.size) ||
       !enif_get_list_length(env, argv[3], &count) || count > 32 ||
       !readonly_limit(env, argv[4], "rows", 500, &max_rows) ||
       !readonly_limit(env, argv[4], "bytes", 1048576, &max_bytes) ||
       !readonly_limit(env, argv[4], "milliseconds", 2000, &milliseconds) ||
       !readonly_limit(env, argv[4], "operations", 1000000, &context.max_operations) ||
       !readonly_limit(env, argv[4], "columns", 32, &max_columns))
        return readonly_error(env, "invalid_argument", "Invalid SQL query or budget");
    if(!connection->db || !connection->private_memory)
        return readonly_error(env, "invalid_argument", "Query requires a private :memory: database");
    sqlite3_int64 heap = sqlite3_hard_heap_limit64(-1);
    if(heap <= 0 || heap > RO_HEAP_BYTES)
        return readonly_error(env, "unsupported_build", "Initialize the satellite SQLite heap ceiling first");
    ERL_NIF_TERM head, tail = argv[3];
    for(unsigned i = 0; i < count; i++) {
        enif_get_list_cell(env, tail, &head, &tail);
        if(!enif_inspect_binary(env, head, &context.tables[i]) ||
           context.tables[i].size == 0 || context.tables[i].size > 128 ||
           memchr(context.tables[i].data, 0, context.tables[i].size) ||
           !readonly_utf8(context.tables[i].data, context.tables[i].size))
            return readonly_error(env, "invalid_argument", "Invalid trusted table allowlist");
    }
    context.table_count = count;
    context.deadline = enif_monotonic_time(ERL_NIF_MSEC) + milliseconds;
    sqlite3_stmt *statement = NULL, *extra = NULL;
    const char *remaining = NULL;
    const char *kind = NULL, *message = NULL;
    ERL_NIF_TERM error = 0;
    ERL_NIF_TERM names = enif_make_list(env, 0), rows = enif_make_list(env, 0);
    unsigned bytes = 0, row_count = 0;
    int rc;

    /* These settings are trusted setup, before the authorizer sees model SQL.
     * Every callback remains installed through finalization and reprepare. */
    sqlite3_db_config(connection->db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
    sqlite3_db_config(connection->db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL);
    sqlite3_db_config(connection->db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, NULL);
    /* COUNT(*) can report a NULL database. Reject attached databases and any
     * temporary schema first so that this callback shape can name only main. */
    if(sqlite3_db_name(connection->db, 2) != NULL)
        return readonly_error(env, "read_only_denied", "Attached databases are forbidden");
    sqlite3_stmt *temp_probe = NULL;
    rc = sqlite3_prepare_v2(connection->db, "SELECT 1 FROM temp.sqlite_schema LIMIT 1", -1, &temp_probe, NULL);
    if(rc == SQLITE_OK) rc = sqlite3_step(temp_probe);
    sqlite3_finalize(temp_probe);
    if(rc != SQLITE_DONE)
        return readonly_error(env, "read_only_denied", "Temporary schema objects are forbidden");

    rc = sqlite3_exec(connection->db, "PRAGMA temp_store=MEMORY; PRAGMA query_only=ON", NULL, NULL, NULL);
    if(rc != SQLITE_OK) return readonly_error(env, "sql_error", sqlite3_errmsg(connection->db));

    sqlite3_limit(connection->db, SQLITE_LIMIT_LENGTH, RO_VALUE_BYTES);
    sqlite3_limit(connection->db, SQLITE_LIMIT_SQL_LENGTH, RO_SQL_BYTES);
    sqlite3_limit(connection->db, SQLITE_LIMIT_COLUMN, 32);
    sqlite3_limit(connection->db, SQLITE_LIMIT_EXPR_DEPTH, 16);
    sqlite3_limit(connection->db, SQLITE_LIMIT_COMPOUND_SELECT, 16);
    sqlite3_limit(connection->db, SQLITE_LIMIT_VDBE_OP, 25000);
    sqlite3_limit(connection->db, SQLITE_LIMIT_FUNCTION_ARG, 16);
    sqlite3_limit(connection->db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 128);
    sqlite3_limit(connection->db, SQLITE_LIMIT_ATTACHED, 0);
    sqlite3_limit(connection->db, SQLITE_LIMIT_VARIABLE_NUMBER, RO_PARAMS);
    sqlite3_set_authorizer(connection->db, readonly_authorizer, &context);
    sqlite3_progress_handler(connection->db, RO_PROGRESS_INTERVAL, readonly_progress, &context);
    rc = sqlite3_prepare_v3(connection->db, (const char *)sql.data, sql.size,
                            SQLITE_PREPARE_NO_VTAB, &statement, &remaining);
    if(rc != SQLITE_OK) goto sqlite_failure;
    if(!statement || !sqlite3_stmt_readonly(statement)) {
        kind = "read_only_denied"; message = "Exactly one read-only statement is required"; goto cleanup;
    }

    /* Preparing the tail recognizes comments and whitespace with SQLite's own
     * grammar; a second statement is forbidden even when it is also a SELECT. */
    rc = sqlite3_prepare_v3(connection->db, remaining,
        (const char *)sql.data + sql.size - remaining, SQLITE_PREPARE_NO_VTAB, &extra, NULL);
    if(rc != SQLITE_OK) goto sqlite_failure;
    if(extra) { kind = "multiple_statements"; message = "Exactly one statement is required"; goto cleanup; }
    rc = readonly_bind(env, statement, argv[2]);
    if(rc == SQLITE_MISUSE) { kind = "invalid_argument"; message = "Invalid query parameters"; goto cleanup; }
    if(rc != SQLITE_OK) goto sqlite_failure;
    int columns = sqlite3_column_count(statement);
    if(columns < 1 || (unsigned)columns > max_columns) {
        kind = "column_limit"; message = "Column budget exceeded"; goto cleanup;
    }
    for(int i = columns - 1; i >= 0; i--) {
        const char *name = sqlite3_column_name(statement, i);
        if(!name) { kind = "memory_limit"; message = "SQLite could not allocate column names"; goto cleanup; }
        size_t size = strlen(name);
        if(size > max_bytes - bytes || !readonly_utf8((const unsigned char *)name, size)) {
            kind = "byte_limit"; message = "Column names exceed output budget"; goto cleanup;
        }
        bytes += size;
        names = enif_make_list_cell(env, make_binary(env, name, size), names);
    }
    while((rc = sqlite3_step(statement)) == SQLITE_ROW) {
        if(readonly_check(&context)) goto sqlite_failure;
        if(++row_count > max_rows) { kind = "row_limit"; message = "Row budget exceeded"; goto cleanup; }
        ERL_NIF_TERM row = enif_make_list(env, 0);
        for(int i = columns - 1; i >= 0; i--) {
            int type = sqlite3_column_type(statement, i);
            unsigned size = 16;
            const unsigned char *text = NULL;
            if(type == SQLITE_FLOAT && !isfinite(sqlite3_column_double(statement, i))) { kind = "non_finite_real"; message = "Non-finite REAL results are not supported"; goto cleanup; }
            if(type == SQLITE_BLOB) { kind = "blob_not_supported"; message = "BLOB results are not supported"; goto cleanup; }
            if(type == SQLITE_TEXT) {
                text = sqlite3_column_text(statement, i);
                int length = sqlite3_column_bytes(statement, i);
                if(!text) { kind = "memory_limit"; message = "SQLite could not allocate result text"; goto cleanup; }
                if(!readonly_utf8(text, length)) { kind = "invalid_text"; message = "Result is not UTF-8 text"; goto cleanup; }
                size += length;
            }
            if(size > max_bytes - bytes) { kind = "byte_limit"; message = "Output byte budget exceeded"; goto cleanup; }
            bytes += size;
            ERL_NIF_TERM cell;
            if(type == SQLITE_NULL) cell = make_atom(env, "null");
            else if(type == SQLITE_INTEGER) cell = enif_make_tuple2(env, make_atom(env, "integer"), enif_make_int64(env, sqlite3_column_int64(statement, i)));
            else if(type == SQLITE_FLOAT) cell = enif_make_tuple2(env, make_atom(env, "real"), enif_make_double(env, sqlite3_column_double(statement, i)));
            else cell = enif_make_tuple2(env, make_atom(env, "text"), make_binary(env, text, size - 16));
            row = enif_make_list_cell(env, cell, row);
        }
        rows = enif_make_list_cell(env, row, rows);
    }
    if(rc != SQLITE_DONE) goto sqlite_failure;
    if(readonly_check(&context)) goto sqlite_failure;
    enif_make_reverse_list(env, rows, &rows);
    goto cleanup;

sqlite_failure:
    kind = context.failure ? context.failure :
        ((rc & 255) == SQLITE_NOMEM ? "memory_limit" :
         (rc == SQLITE_INTERRUPT ? "cancelled" : "sql_error"));
    message = context.failure ? context.failure : sqlite3_errmsg(connection->db);
cleanup:
    /* SQLite owns errmsg until its next API call, so copy it before cleanup. */
    if(kind) error = readonly_error(env, kind, message);

    /* Retire private statements before clearing callbacks that reprepare owns. */
    sqlite3_finalize(extra);
    sqlite3_finalize(statement);
    sqlite3_progress_handler(connection->db, 0, NULL, NULL);
    sqlite3_set_authorizer(connection->db, NULL, NULL);
    if(kind) return error;
    return make_ok_tuple(env, enif_make_tuple2(env, names, rows));
}
