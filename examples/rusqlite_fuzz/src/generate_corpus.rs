//! Generates seed corpus files for the rusqlite fuzzer.
//! Run once: `cargo run --bin generate_corpus -p rusqlite_fuzz`

use candid::Encode;
use std::fs;
use std::path::PathBuf;

#[allow(dead_code)]
mod rusqlite_db_types {
    include!(concat!(env!("OUT_DIR"), "/rusqlite_db_types.rs"));
}
use rusqlite_db_types::*;

fn main() {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    fs::create_dir_all(&corpus_dir).unwrap();

    let mut count = 0;

    // ── Basic operations ────────────────────────────────────────────────

    // Simple CREATE TABLE
    emit(
        &corpus_dir,
        "seed_create_table",
        &mut count,
        &vec![SqlOperation::CreateTable {
            table: "users".into(),
            columns: vec![
                col("id", "INTEGER", true, false, false, None),
                col("name", "TEXT", false, true, false, None),
                col("email", "TEXT", false, false, true, None),
            ],
        }],
    );

    // Create + insert rows
    emit(
        &corpus_dir,
        "seed_insert",
        &mut count,
        &vec![
            create_items_table(),
            insert_item(1, "Widget", 9.99),
            insert_item(2, "Gadget", 19.99),
        ],
    );

    // Select with WHERE
    emit(
        &corpus_dir,
        "seed_select_where",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(42, "hello"),
            select_ab_where(WhereClause::Eq {
                col: "a".into(),
                val: SqlValue::Integer(42),
            }),
        ],
    );

    // Update + Delete
    emit(
        &corpus_dir,
        "seed_update_delete",
        &mut count,
        &vec![
            create_kv_table(),
            insert_kv("key1", &[1, 2, 3]),
            SqlOperation::Update {
                table: "kv".into(),
                assignments: vec![assign("v", SqlValue::Blob(vec![4, 5, 6].into()))],
                where_clause: Some(Box::new(where_eq_text("k", "key1"))),
            },
            SqlOperation::Delete {
                table: "kv".into(),
                where_clause: Some(Box::new(where_eq_text("k", "key1"))),
            },
        ],
    );

    // Transaction + raw SQL
    emit(
        &corpus_dir,
        "seed_transaction",
        &mut count,
        &vec![
            SqlOperation::CreateTable {
                table: "tx_test".into(),
                columns: vec![col("x", "INTEGER", false, false, false, None)],
            },
            SqlOperation::BeginTransaction,
            SqlOperation::Insert {
                table: "tx_test".into(),
                columns: vec!["x".into()],
                values: vec![SqlValue::Integer(100)],
            },
            SqlOperation::Commit,
            SqlOperation::RawSql {
                sql: "SELECT COUNT(*) FROM tx_test".into(),
            },
        ],
    );

    // JOIN
    emit(
        &corpus_dir,
        "seed_join",
        &mut count,
        &vec![
            SqlOperation::CreateTable {
                table: "orders".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col("customer_id", "INTEGER", false, true, false, None),
                    col("amount", "REAL", false, false, false, None),
                ],
            },
            SqlOperation::CreateTable {
                table: "customers".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col("name", "TEXT", false, true, false, None),
                ],
            },
            SqlOperation::Insert {
                table: "customers".into(),
                columns: vec!["id".into(), "name".into()],
                values: vec![SqlValue::Integer(1), SqlValue::Text("Alice".into())],
            },
            SqlOperation::Insert {
                table: "orders".into(),
                columns: vec!["id".into(), "customer_id".into(), "amount".into()],
                values: vec![
                    SqlValue::Integer(1),
                    SqlValue::Integer(1),
                    SqlValue::Real(50.0),
                ],
            },
            SqlOperation::Select {
                table: "orders".into(),
                columns: vec!["name".into(), "amount".into()],
                where_clause: None,
                joins: vec![JoinClause {
                    join_type: JoinType::Inner,
                    table: "customers".into(),
                    on_left_col: "customer_id".into(),
                    on_right_col: "id".into(),
                }],
                aggregates: vec![],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
        ],
    );

    // Aggregates + GROUP BY + ORDER BY
    emit(
        &corpus_dir,
        "seed_aggregate",
        &mut count,
        &vec![
            create_sales_table(),
            insert_sale("east", 100.0),
            insert_sale("west", 200.0),
            insert_sale("east", 150.0),
            SqlOperation::Select {
                table: "sales".into(),
                columns: vec!["region".into()],
                where_clause: None,
                joins: vec![],
                aggregates: vec![
                    agg(AggregateExprAggFunc::Sum, "amount"),
                    agg(AggregateExprAggFunc::Count, "amount"),
                ],
                group_by: vec!["region".into()],
                order_by: vec![order_by("region", OrderDir::Asc)],
                limit: Some(10),
            },
        ],
    );

    // Index + Vacuum
    emit(
        &corpus_dir,
        "seed_index_vacuum",
        &mut count,
        &vec![
            SqlOperation::CreateTable {
                table: "indexed".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col("val", "TEXT", false, false, false, None),
                ],
            },
            SqlOperation::CreateIndex {
                table: "indexed".into(),
                columns: vec!["val".into()],
                unique: false,
            },
            SqlOperation::Vacuum,
        ],
    );

    // ── Numeric edge cases ──────────────────────────────────────────────

    // INT64 boundary values
    emit(
        &corpus_dir,
        "seed_int_boundaries",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(i64::MAX, "max"),
            insert_ab(i64::MIN, "min"),
            insert_ab(0, "zero"),
            insert_ab(-1, "neg_one"),
            insert_ab(1, "one"),
            // Select with boundary comparisons
            select_ab_where(WhereClause::Gt {
                col: "a".into(),
                val: SqlValue::Integer(i64::MAX - 1),
            }),
            select_ab_where(WhereClause::Lt {
                col: "a".into(),
                val: SqlValue::Integer(i64::MIN + 1),
            }),
        ],
    );

    // Float edge cases: extreme values, near-zero, negative zero
    emit(
        &corpus_dir,
        "seed_float_extremes",
        &mut count,
        &vec![
            SqlOperation::CreateTable {
                table: "floats".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col("v", "REAL", false, false, false, None),
                ],
            },
            insert_float(1, f64::MAX),
            insert_float(2, f64::MIN),
            insert_float(3, f64::MIN_POSITIVE), // smallest positive normal
            insert_float(4, f64::EPSILON),
            insert_float(5, f64::INFINITY),
            insert_float(6, f64::NEG_INFINITY),
            insert_float(7, f64::NAN),
            insert_float(8, -0.0),
            insert_float(9, 1e308),
            insert_float(10, -1e308),
            insert_float(11, 5e-324), // smallest subnormal
            SqlOperation::Select {
                table: "floats".into(),
                columns: vec!["id".into(), "v".into()],
                where_clause: None,
                joins: vec![],
                aggregates: vec![
                    agg(AggregateExprAggFunc::Sum, "v"),
                    agg(AggregateExprAggFunc::Avg, "v"),
                    agg(AggregateExprAggFunc::Min, "v"),
                    agg(AggregateExprAggFunc::Max, "v"),
                ],
                group_by: vec![],
                order_by: vec![order_by("v", OrderDir::Asc)],
                limit: None,
            },
        ],
    );

    // ── NULL edge cases ─────────────────────────────────────────────────

    // Insert NULLs everywhere, including in primary key (SQLite allows this)
    emit(
        &corpus_dir,
        "seed_null_primary_key",
        &mut count,
        &vec![
            SqlOperation::CreateTable {
                table: "npk".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col("val", "TEXT", false, false, false, None),
                ],
            },
            SqlOperation::Insert {
                table: "npk".into(),
                columns: vec!["id".into(), "val".into()],
                values: vec![SqlValue::Null, SqlValue::Text("null_pk".into())],
            },
            SqlOperation::Insert {
                table: "npk".into(),
                columns: vec!["id".into(), "val".into()],
                values: vec![SqlValue::Null, SqlValue::Null],
            },
            // NULL comparisons
            select_from(
                "npk",
                vec!["id", "val"],
                Some(WhereClause::IsNull { col: "id".into() }),
            ),
            select_from(
                "npk",
                vec!["id", "val"],
                Some(WhereClause::Eq {
                    col: "id".into(),
                    val: SqlValue::Null,
                }),
            ),
        ],
    );

    // NULLs in UNIQUE columns (multiple NULLs should be allowed)
    emit(
        &corpus_dir,
        "seed_null_unique",
        &mut count,
        &vec![
            SqlOperation::CreateTable {
                table: "nu".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col("u", "TEXT", false, false, true, None),
                ],
            },
            SqlOperation::Insert {
                table: "nu".into(),
                columns: vec!["id".into(), "u".into()],
                values: vec![SqlValue::Integer(1), SqlValue::Null],
            },
            SqlOperation::Insert {
                table: "nu".into(),
                columns: vec!["id".into(), "u".into()],
                values: vec![SqlValue::Integer(2), SqlValue::Null],
            },
            SqlOperation::Insert {
                table: "nu".into(),
                columns: vec!["id".into(), "u".into()],
                values: vec![SqlValue::Integer(3), SqlValue::Null],
            },
        ],
    );

    // NULL in aggregate functions
    emit(
        &corpus_dir,
        "seed_null_aggregates",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab_nullable(SqlValue::Null, SqlValue::Text("a".into())),
            insert_ab_nullable(SqlValue::Integer(1), SqlValue::Null),
            insert_ab_nullable(SqlValue::Null, SqlValue::Null),
            insert_ab_nullable(SqlValue::Integer(2), SqlValue::Text("b".into())),
            SqlOperation::Select {
                table: "t".into(),
                columns: vec!["b".into()],
                where_clause: None,
                joins: vec![],
                aggregates: vec![
                    agg(AggregateExprAggFunc::Count, "a"),
                    agg(AggregateExprAggFunc::Sum, "a"),
                    agg(AggregateExprAggFunc::Avg, "a"),
                    agg(AggregateExprAggFunc::Min, "a"),
                    agg(AggregateExprAggFunc::Max, "a"),
                    agg(AggregateExprAggFunc::GroupConcat, "b"),
                ],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
        ],
    );

    // NULL in WHERE clause operators
    emit(
        &corpus_dir,
        "seed_null_where_ops",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab_nullable(SqlValue::Null, SqlValue::Null),
            insert_ab_nullable(SqlValue::Integer(1), SqlValue::Text("x".into())),
            // BETWEEN with NULL
            select_ab_where(WhereClause::Between {
                col: "a".into(),
                low: SqlValue::Null,
                high: SqlValue::Integer(10),
            }),
            // InList with NULL
            select_ab_where(WhereClause::InList {
                col: "a".into(),
                vals: vec![SqlValue::Null, SqlValue::Integer(1)],
            }),
            // LIKE on NULL
            select_ab_where(WhereClause::Like {
                col: "b".into(),
                pattern: "%".into(),
            }),
        ],
    );

    // ── String / text edge cases ────────────────────────────────────────

    // Empty strings, special characters, SQL metacharacters
    emit(
        &corpus_dir,
        "seed_string_edge",
        &mut count,
        &vec![
            create_kv_table(),
            insert_kv_text("", "empty_key"),
            insert_kv_text("'", "single_quote"),
            insert_kv_text("''", "double_single_quote"),
            insert_kv_text("\"", "double_quote"),
            insert_kv_text("\\", "backslash"),
            insert_kv_text("\0", "nul_byte"),
            insert_kv_text("\t\n\r", "whitespace_control"),
            insert_kv_text("%", "percent"),
            insert_kv_text("_", "underscore"),
            insert_kv_text("%;DROP TABLE kv;--", "injection_attempt"),
            // LIKE with special patterns
            select_kv_like("'%"),
            select_kv_like("_%"),
            select_kv_like("%%"),
            select_kv_like(""),
        ],
    );

    // Unicode: multibyte, emoji, RTL, combining chars
    emit(
        &corpus_dir,
        "seed_unicode",
        &mut count,
        &vec![
            create_kv_table(),
            insert_kv_text("日本語テスト", "japanese"),
            insert_kv_text("مرحبا", "arabic_rtl"),
            insert_kv_text("🎉🔥💀", "emoji"),
            insert_kv_text("é", "e_acute_composed"), // U+00E9
            insert_kv_text("é", "e_acute_decomposed"), // e + U+0301
            insert_kv_text("Z̤̈", "combining_multiple"),
            insert_kv_text("\u{200B}", "zero_width_space"),
            insert_kv_text("\u{FEFF}", "bom"),
            insert_kv_text("\u{202E}abc", "rtl_override"),
            insert_kv_text(
                "a\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}",
                "stacked_diacritics",
            ),
        ],
    );

    // Very long string
    emit(
        &corpus_dir,
        "seed_long_string",
        &mut count,
        &vec![
            create_kv_table(),
            insert_kv_text(&"A".repeat(10000), "long_value"),
            select_kv_like(&format!("{}%", "A".repeat(5000))),
        ],
    );

    // ── BLOB edge cases ─────────────────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_blob_edge",
        &mut count,
        &vec![
            create_kv_table(),
            insert_kv("empty_blob", &[]),
            insert_kv("single_zero", &[0]),
            insert_kv("single_ff", &[0xFF]),
            insert_kv("all_zeros", &vec![0u8; 1024]),
            insert_kv("all_ones", &vec![0xFF; 1024]),
            // Large blob
            insert_kv("large_blob", &vec![0xAB; 65536]),
        ],
    );

    // ── Type coercion / affinity edge cases ─────────────────────────────

    // Insert mismatched types into columns
    emit(
        &corpus_dir,
        "seed_type_coercion",
        &mut count,
        &vec![
            SqlOperation::CreateTable {
                table: "typed".into(),
                columns: vec![
                    col("int_col", "INTEGER", false, false, false, None),
                    col("real_col", "REAL", false, false, false, None),
                    col("text_col", "TEXT", false, false, false, None),
                    col("blob_col", "BLOB", false, false, false, None),
                    col("any_col", "", false, false, false, None), // no type = NUMERIC affinity
                ],
            },
            // Text in integer column
            SqlOperation::Insert {
                table: "typed".into(),
                columns: vec![
                    "int_col".into(),
                    "real_col".into(),
                    "text_col".into(),
                    "blob_col".into(),
                    "any_col".into(),
                ],
                values: vec![
                    SqlValue::Text("not_a_number".into()),
                    SqlValue::Text("3.14".into()),
                    SqlValue::Integer(42),
                    SqlValue::Text("text_in_blob".into()),
                    SqlValue::Blob(vec![1, 2, 3].into()),
                ],
            },
            // Integer in text column, real in integer column
            SqlOperation::Insert {
                table: "typed".into(),
                columns: vec![
                    "int_col".into(),
                    "real_col".into(),
                    "text_col".into(),
                    "blob_col".into(),
                    "any_col".into(),
                ],
                values: vec![
                    SqlValue::Real(1.23),
                    SqlValue::Integer(42),
                    SqlValue::Real(f64::NAN),
                    SqlValue::Integer(0),
                    SqlValue::Null,
                ],
            },
        ],
    );

    // ── Default values ──────────────────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_defaults",
        &mut count,
        &vec![
            SqlOperation::CreateTable {
                table: "defs".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col(
                        "n",
                        "INTEGER",
                        false,
                        false,
                        false,
                        Some(SqlValue::Integer(0)),
                    ),
                    col(
                        "s",
                        "TEXT",
                        false,
                        false,
                        false,
                        Some(SqlValue::Text("default".into())),
                    ),
                    col("r", "REAL", false, false, false, Some(SqlValue::Real(1.0))),
                    col(
                        "b",
                        "BLOB",
                        false,
                        false,
                        false,
                        Some(SqlValue::Blob(vec![].into())),
                    ),
                    col(
                        "null_default",
                        "TEXT",
                        false,
                        false,
                        false,
                        Some(SqlValue::Null),
                    ),
                ],
            },
            // Insert with only pk, rest should use defaults
            SqlOperation::Insert {
                table: "defs".into(),
                columns: vec!["id".into()],
                values: vec![SqlValue::Integer(1)],
            },
        ],
    );

    // ── Deeply nested WHERE clauses ─────────────────────────────────────

    // Deep AND/OR nesting
    emit(
        &corpus_dir,
        "seed_deep_where",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "a"),
            insert_ab(2, "b"),
            insert_ab(3, "c"),
            select_ab_where(deep_and_chain(20)),
            select_ab_where(deep_or_chain(20)),
            // Mixed nested AND/OR
            select_ab_where(WhereClause::And {
                left: Box::new(WhereClause::Or {
                    left: Box::new(WhereClause::Eq {
                        col: "a".into(),
                        val: SqlValue::Integer(1),
                    }),
                    right: Box::new(WhereClause::Eq {
                        col: "a".into(),
                        val: SqlValue::Integer(2),
                    }),
                }),
                right: Box::new(WhereClause::Or {
                    left: Box::new(WhereClause::Like {
                        col: "b".into(),
                        pattern: "%a%".into(),
                    }),
                    right: Box::new(WhereClause::IsNull { col: "b".into() }),
                }),
            }),
        ],
    );

    // Contradictory WHERE clause (always false)
    emit(
        &corpus_dir,
        "seed_contradictory_where",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "x"),
            select_ab_where(WhereClause::And {
                left: Box::new(WhereClause::Eq {
                    col: "a".into(),
                    val: SqlValue::Integer(1),
                }),
                right: Box::new(WhereClause::NotEq {
                    col: "a".into(),
                    val: SqlValue::Integer(1),
                }),
            }),
        ],
    );

    // ── Empty table operations ──────────────────────────────────────────

    // Select / aggregate / join on empty tables
    emit(
        &corpus_dir,
        "seed_empty_table_ops",
        &mut count,
        &vec![
            create_ab_table(),
            SqlOperation::CreateTable {
                table: "empty2".into(),
                columns: vec![
                    col("x", "INTEGER", true, false, false, None),
                    col("y", "TEXT", false, false, false, None),
                ],
            },
            // Select from empty
            select_from("t", vec!["a", "b"], None),
            // Aggregate on empty table
            SqlOperation::Select {
                table: "t".into(),
                columns: vec![],
                where_clause: None,
                joins: vec![],
                aggregates: vec![
                    agg(AggregateExprAggFunc::Count, "a"),
                    agg(AggregateExprAggFunc::Sum, "a"),
                    agg(AggregateExprAggFunc::Avg, "a"),
                ],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
            // JOIN on two empty tables
            SqlOperation::Select {
                table: "t".into(),
                columns: vec!["a".into(), "y".into()],
                where_clause: None,
                joins: vec![JoinClause {
                    join_type: JoinType::Inner,
                    table: "empty2".into(),
                    on_left_col: "a".into(),
                    on_right_col: "x".into(),
                }],
                aggregates: vec![],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
            // LEFT JOIN on empty table
            SqlOperation::Select {
                table: "t".into(),
                columns: vec!["a".into(), "y".into()],
                where_clause: None,
                joins: vec![JoinClause {
                    join_type: JoinType::Left,
                    table: "empty2".into(),
                    on_left_col: "a".into(),
                    on_right_col: "x".into(),
                }],
                aggregates: vec![],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
            // Delete from empty table
            SqlOperation::Delete {
                table: "t".into(),
                where_clause: None,
            },
            // VACUUM after all operations on empty db
            SqlOperation::Vacuum,
        ],
    );

    // ── Self-join ───────────────────────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_self_join",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "a"),
            insert_ab(2, "b"),
            insert_ab(3, "a"),
            SqlOperation::Select {
                table: "t".into(),
                columns: vec!["a".into(), "b".into()],
                where_clause: None,
                joins: vec![JoinClause {
                    join_type: JoinType::Inner,
                    table: "t".into(),
                    on_left_col: "a".into(),
                    on_right_col: "a".into(),
                }],
                aggregates: vec![],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
        ],
    );

    // ── Cross join (cartesian product) ──────────────────────────────────

    emit(
        &corpus_dir,
        "seed_cross_join",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "x"),
            insert_ab(2, "y"),
            SqlOperation::CreateTable {
                table: "t2".into(),
                columns: vec![
                    col("c", "INTEGER", false, false, false, None),
                    col("d", "TEXT", false, false, false, None),
                ],
            },
            SqlOperation::Insert {
                table: "t2".into(),
                columns: vec!["c".into(), "d".into()],
                values: vec![SqlValue::Integer(10), SqlValue::Text("p".into())],
            },
            SqlOperation::Insert {
                table: "t2".into(),
                columns: vec!["c".into(), "d".into()],
                values: vec![SqlValue::Integer(20), SqlValue::Text("q".into())],
            },
            SqlOperation::Select {
                table: "t".into(),
                columns: vec!["a".into(), "b".into(), "c".into(), "d".into()],
                where_clause: None,
                joins: vec![JoinClause {
                    join_type: JoinType::Cross,
                    table: "t2".into(),
                    on_left_col: "a".into(),
                    on_right_col: "c".into(),
                }],
                aggregates: vec![],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
        ],
    );

    // ── JOIN with contradictory ON (always-false) ───────────────────────

    emit(
        &corpus_dir,
        "seed_join_false_on",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "x"),
            SqlOperation::CreateTable {
                table: "t2".into(),
                columns: vec![col("c", "INTEGER", false, false, false, None)],
            },
            SqlOperation::Insert {
                table: "t2".into(),
                columns: vec!["c".into()],
                values: vec![SqlValue::Integer(999)],
            },
            // LEFT JOIN where no rows can match
            SqlOperation::Select {
                table: "t".into(),
                columns: vec!["a".into(), "c".into()],
                where_clause: None,
                joins: vec![JoinClause {
                    join_type: JoinType::Left,
                    table: "t2".into(),
                    on_left_col: "a".into(),
                    on_right_col: "c".into(),
                }],
                aggregates: vec![],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
        ],
    );

    // ── GROUP BY edge cases ─────────────────────────────────────────────

    // GROUP BY with no matching rows
    emit(
        &corpus_dir,
        "seed_group_by_no_rows",
        &mut count,
        &vec![
            create_sales_table(),
            SqlOperation::Select {
                table: "sales".into(),
                columns: vec!["region".into()],
                where_clause: Some(Box::new(WhereClause::Eq {
                    col: "region".into(),
                    val: SqlValue::Text("nonexistent".into()),
                })),
                joins: vec![],
                aggregates: vec![agg(AggregateExprAggFunc::Count, "amount")],
                group_by: vec!["region".into()],
                order_by: vec![],
                limit: None,
            },
        ],
    );

    // GROUP BY with NULLs
    emit(
        &corpus_dir,
        "seed_group_by_nulls",
        &mut count,
        &vec![
            create_sales_table(),
            insert_sale("east", 100.0),
            insert_sale_nullable(SqlValue::Null, SqlValue::Real(200.0)),
            insert_sale_nullable(SqlValue::Null, SqlValue::Real(300.0)),
            insert_sale("east", 150.0),
            SqlOperation::Select {
                table: "sales".into(),
                columns: vec!["region".into()],
                where_clause: None,
                joins: vec![],
                aggregates: vec![
                    agg(AggregateExprAggFunc::Count, "amount"),
                    agg(AggregateExprAggFunc::Sum, "amount"),
                ],
                group_by: vec!["region".into()],
                order_by: vec![],
                limit: None,
            },
        ],
    );

    // All aggregate functions
    emit(
        &corpus_dir,
        "seed_all_aggregates",
        &mut count,
        &vec![
            create_sales_table(),
            insert_sale("a", 1.0),
            insert_sale("a", 2.0),
            insert_sale("b", 3.0),
            SqlOperation::Select {
                table: "sales".into(),
                columns: vec!["region".into()],
                where_clause: None,
                joins: vec![],
                aggregates: vec![
                    agg(AggregateExprAggFunc::Count, "amount"),
                    agg(AggregateExprAggFunc::Sum, "amount"),
                    agg(AggregateExprAggFunc::Avg, "amount"),
                    agg(AggregateExprAggFunc::Min, "amount"),
                    agg(AggregateExprAggFunc::Max, "amount"),
                    agg(AggregateExprAggFunc::GroupConcat, "region"),
                ],
                group_by: vec!["region".into()],
                order_by: vec![order_by("region", OrderDir::Desc)],
                limit: None,
            },
        ],
    );

    // ── ORDER BY / LIMIT edge cases ─────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_order_limit_edge",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(3, "c"),
            insert_ab(1, "a"),
            insert_ab(2, "b"),
            insert_ab_nullable(SqlValue::Null, SqlValue::Text("null_first".into())),
            // ORDER BY with NULLs (nulls sort first in SQLite)
            select_ordered("t", vec!["a", "b"], "a", OrderDir::Asc, None),
            select_ordered("t", vec!["a", "b"], "a", OrderDir::Desc, None),
            // LIMIT 0
            select_ordered("t", vec!["a", "b"], "a", OrderDir::Asc, Some(0)),
            // LIMIT 1
            select_ordered("t", vec!["a", "b"], "a", OrderDir::Asc, Some(1)),
            // LIMIT larger than result set
            select_ordered("t", vec!["a", "b"], "a", OrderDir::Asc, Some(u32::MAX)),
        ],
    );

    // ── Index edge cases ────────────────────────────────────────────────

    // Unique index with NULLs
    emit(
        &corpus_dir,
        "seed_index_null",
        &mut count,
        &vec![
            create_ab_table(),
            SqlOperation::CreateIndex {
                table: "t".into(),
                columns: vec!["b".into()],
                unique: true,
            },
            // Multiple NULLs should be allowed even with unique index
            insert_ab_nullable(SqlValue::Integer(1), SqlValue::Null),
            insert_ab_nullable(SqlValue::Integer(2), SqlValue::Null),
            insert_ab_nullable(SqlValue::Integer(3), SqlValue::Text("unique_val".into())),
        ],
    );

    // Multi-column index
    emit(
        &corpus_dir,
        "seed_index_multi_col",
        &mut count,
        &vec![
            create_ab_table(),
            SqlOperation::CreateIndex {
                table: "t".into(),
                columns: vec!["a".into(), "b".into()],
                unique: true,
            },
            insert_ab(1, "a"),
            insert_ab(2, "a"), // same b, different a — should be fine
            insert_ab(1, "b"), // same a, different b — should be fine
            select_ab_where(WhereClause::And {
                left: Box::new(WhereClause::Eq {
                    col: "a".into(),
                    val: SqlValue::Integer(1),
                }),
                right: Box::new(WhereClause::Eq {
                    col: "b".into(),
                    val: SqlValue::Text("a".into()),
                }),
            }),
        ],
    );

    // Index on table then drop + recreate
    emit(
        &corpus_dir,
        "seed_index_drop_recreate",
        &mut count,
        &vec![
            create_ab_table(),
            SqlOperation::CreateIndex {
                table: "t".into(),
                columns: vec!["a".into()],
                unique: false,
            },
            insert_ab(1, "x"),
            SqlOperation::DropTable { table: "t".into() },
            create_ab_table(),
            insert_ab(1, "y"),
        ],
    );

    // ── Transaction edge cases ──────────────────────────────────────────

    // Rollback undoes changes
    emit(
        &corpus_dir,
        "seed_rollback",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "before"),
            SqlOperation::BeginTransaction,
            insert_ab(2, "should_disappear"),
            SqlOperation::Delete {
                table: "t".into(),
                where_clause: Some(Box::new(WhereClause::Eq {
                    col: "a".into(),
                    val: SqlValue::Integer(1),
                })),
            },
            SqlOperation::Rollback,
            // Only row 1 should remain
            select_from("t", vec!["a", "b"], None),
        ],
    );

    // Begin without commit (orphaned transaction)
    emit(
        &corpus_dir,
        "seed_orphan_transaction",
        &mut count,
        &vec![
            create_ab_table(),
            SqlOperation::BeginTransaction,
            insert_ab(1, "orphan"),
            // No commit or rollback — tests implicit behavior
        ],
    );

    // Commit/Rollback without begin
    emit(
        &corpus_dir,
        "seed_commit_no_begin",
        &mut count,
        &vec![create_ab_table(), SqlOperation::Commit],
    );

    emit(
        &corpus_dir,
        "seed_rollback_no_begin",
        &mut count,
        &vec![create_ab_table(), SqlOperation::Rollback],
    );

    // Multiple sequential transactions
    emit(
        &corpus_dir,
        "seed_multi_transaction",
        &mut count,
        &vec![
            create_ab_table(),
            SqlOperation::BeginTransaction,
            insert_ab(1, "tx1"),
            SqlOperation::Commit,
            SqlOperation::BeginTransaction,
            insert_ab(2, "tx2"),
            SqlOperation::Rollback,
            SqlOperation::BeginTransaction,
            insert_ab(3, "tx3"),
            SqlOperation::Commit,
            select_from("t", vec!["a", "b"], None),
        ],
    );

    // ── DROP TABLE edge cases ───────────────────────────────────────────

    // Drop then re-create same name
    emit(
        &corpus_dir,
        "seed_drop_recreate",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "old"),
            SqlOperation::DropTable { table: "t".into() },
            create_ab_table(),
            insert_ab(2, "new"),
            select_from("t", vec!["a", "b"], None),
        ],
    );

    // Drop nonexistent table (should error gracefully)
    emit(
        &corpus_dir,
        "seed_drop_nonexistent",
        &mut count,
        &vec![SqlOperation::DropTable {
            table: "does_not_exist".into(),
        }],
    );

    // ── Large batch operations ──────────────────────────────────────────

    // Many inserts in one batch
    emit(&corpus_dir, "seed_bulk_insert", &mut count, &{
        let mut ops: Vec<SqlOperation> = vec![create_ab_table()];
        for i in 0..500 {
            ops.push(insert_ab(i, &format!("row_{i}")));
        }
        // Aggregate all rows
        ops.push(SqlOperation::Select {
            table: "t".into(),
            columns: vec![],
            where_clause: None,
            joins: vec![],
            aggregates: vec![agg(AggregateExprAggFunc::Count, "a")],
            group_by: vec![],
            order_by: vec![],
            limit: None,
        });
        ops
    });

    // Insert then delete all, then vacuum
    emit(&corpus_dir, "seed_insert_delete_all_vacuum", &mut count, &{
        let mut ops: Vec<SqlOperation> = vec![create_ab_table()];
        for i in 0..100 {
            ops.push(insert_ab(i, &format!("v{i}")));
        }
        ops.push(SqlOperation::Delete {
            table: "t".into(),
            where_clause: None,
        });
        ops.push(SqlOperation::Vacuum);
        ops.push(select_from("t", vec!["a", "b"], None));
        ops
    });

    // ── Many columns ────────────────────────────────────────────────────

    emit(&corpus_dir, "seed_many_columns", &mut count, &{
        let cols: Vec<ColumnDef> = (0..100)
            .map(|i| col(&format!("c{i}"), "TEXT", i == 0, false, false, None))
            .collect();
        let col_names: Vec<String> = (0..100).map(|i| format!("c{i}")).collect();
        let values: Vec<SqlValue> = (0..100)
            .map(|i| SqlValue::Text(format!("val_{i}")))
            .collect();
        vec![
            SqlOperation::CreateTable {
                table: "wide".into(),
                columns: cols,
            },
            SqlOperation::Insert {
                table: "wide".into(),
                columns: col_names.clone(),
                values,
            },
            SqlOperation::Select {
                table: "wide".into(),
                columns: col_names,
                where_clause: None,
                joins: vec![],
                aggregates: vec![],
                group_by: vec![],
                order_by: vec![],
                limit: None,
            },
        ]
    });

    // ── Raw SQL edge cases ──────────────────────────────────────────────

    emit(&corpus_dir, "seed_raw_sql_edge", &mut count, &vec![
        // Empty SQL
        SqlOperation::RawSql { sql: "".into() },
        // Whitespace only
        SqlOperation::RawSql { sql: "   \n\t  ".into() },
        // Multiple statements separated by semicolons
        SqlOperation::RawSql { sql: "SELECT 1; SELECT 2; SELECT 3".into() },
        // Division by zero (SQLite returns NULL)
        SqlOperation::RawSql { sql: "SELECT 1/0, 1%0".into() },
        // typeof() on various values
        SqlOperation::RawSql { sql: "SELECT typeof(NULL), typeof(1), typeof(1.0), typeof('text'), typeof(X'00')".into() },
        // CAST edge cases
        SqlOperation::RawSql { sql: "SELECT CAST('not_a_number' AS INTEGER), CAST('' AS INTEGER), CAST(NULL AS TEXT)".into() },
        // Large expression
        SqlOperation::RawSql { sql: "SELECT 9223372036854775807 + 1".into() },
        SqlOperation::RawSql { sql: "SELECT -9223372036854775808 - 1".into() },
        // Comment injection
        SqlOperation::RawSql { sql: "SELECT 1 -- comment".into() },
        SqlOperation::RawSql { sql: "SELECT /* block comment */ 1".into() },
        // Reserved words as identifiers
        SqlOperation::RawSql { sql: "CREATE TABLE \"select\" (\"from\" TEXT, \"where\" INTEGER)".into() },
        SqlOperation::RawSql { sql: "INSERT INTO \"select\" (\"from\", \"where\") VALUES ('test', 42)".into() },
        SqlOperation::RawSql { sql: "SELECT \"from\", \"where\" FROM \"select\"".into() },
        // Recursive CTE
        SqlOperation::RawSql {
            sql: "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 100) SELECT x FROM cnt".into(),
        },
        // EXPLAIN
        SqlOperation::RawSql { sql: "EXPLAIN SELECT 1".into() },
        // INSERT OR IGNORE / INSERT OR REPLACE
        SqlOperation::RawSql { sql: "CREATE TABLE IF NOT EXISTS ior (id INTEGER PRIMARY KEY, v TEXT)".into() },
        SqlOperation::RawSql { sql: "INSERT OR IGNORE INTO ior VALUES (1, 'first')".into() },
        SqlOperation::RawSql { sql: "INSERT OR IGNORE INTO ior VALUES (1, 'duplicate')".into() },
        SqlOperation::RawSql { sql: "INSERT OR REPLACE INTO ior VALUES (1, 'replaced')".into() },
        // Subquery in INSERT
        SqlOperation::RawSql { sql: "CREATE TABLE IF NOT EXISTS sub_src (x INTEGER)".into() },
        SqlOperation::RawSql { sql: "INSERT INTO sub_src VALUES (1), (2), (3)".into() },
        SqlOperation::RawSql { sql: "CREATE TABLE IF NOT EXISTS sub_dst (x INTEGER)".into() },
        SqlOperation::RawSql { sql: "INSERT INTO sub_dst SELECT x FROM sub_src".into() },
    ]);

    // ── PRAGMA edge cases (via raw SQL) ─────────────────────────────────

    emit(
        &corpus_dir,
        "seed_raw_sql_pragma",
        &mut count,
        &vec![
            SqlOperation::RawSql {
                sql: "PRAGMA integrity_check".into(),
            },
            SqlOperation::RawSql {
                sql: "PRAGMA table_info('sqlite_master')".into(),
            },
            SqlOperation::RawSql {
                sql: "PRAGMA journal_mode".into(),
            },
            SqlOperation::RawSql {
                sql: "PRAGMA foreign_keys = ON".into(),
            },
            SqlOperation::RawSql {
                sql: "PRAGMA page_count".into(),
            },
            SqlOperation::RawSql {
                sql: "PRAGMA freelist_count".into(),
            },
        ],
    );

    // ── Complex multi-table scenario ────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_complex_scenario",
        &mut count,
        &vec![
            // Create a schema with multiple related tables
            SqlOperation::CreateTable {
                table: "departments".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col("name", "TEXT", false, true, true, None),
                ],
            },
            SqlOperation::CreateTable {
                table: "employees".into(),
                columns: vec![
                    col("id", "INTEGER", true, false, false, None),
                    col("name", "TEXT", false, true, false, None),
                    col("dept_id", "INTEGER", false, false, false, None),
                    col("salary", "REAL", false, false, false, None),
                    col("hired", "TEXT", false, false, false, None),
                ],
            },
            SqlOperation::CreateIndex {
                table: "employees".into(),
                columns: vec!["dept_id".into()],
                unique: false,
            },
            SqlOperation::CreateIndex {
                table: "employees".into(),
                columns: vec!["salary".into()],
                unique: false,
            },
            // Populate
            SqlOperation::BeginTransaction,
            SqlOperation::Insert {
                table: "departments".into(),
                columns: vec!["id".into(), "name".into()],
                values: vec![SqlValue::Integer(1), SqlValue::Text("Engineering".into())],
            },
            SqlOperation::Insert {
                table: "departments".into(),
                columns: vec!["id".into(), "name".into()],
                values: vec![SqlValue::Integer(2), SqlValue::Text("Sales".into())],
            },
            SqlOperation::Insert {
                table: "employees".into(),
                columns: vec![
                    "id".into(),
                    "name".into(),
                    "dept_id".into(),
                    "salary".into(),
                    "hired".into(),
                ],
                values: vec![
                    SqlValue::Integer(1),
                    SqlValue::Text("Alice".into()),
                    SqlValue::Integer(1),
                    SqlValue::Real(120000.0),
                    SqlValue::Text("2020-01-15".into()),
                ],
            },
            SqlOperation::Insert {
                table: "employees".into(),
                columns: vec![
                    "id".into(),
                    "name".into(),
                    "dept_id".into(),
                    "salary".into(),
                    "hired".into(),
                ],
                values: vec![
                    SqlValue::Integer(2),
                    SqlValue::Text("Bob".into()),
                    SqlValue::Integer(1),
                    SqlValue::Real(95000.0),
                    SqlValue::Text("2021-06-01".into()),
                ],
            },
            SqlOperation::Insert {
                table: "employees".into(),
                columns: vec![
                    "id".into(),
                    "name".into(),
                    "dept_id".into(),
                    "salary".into(),
                    "hired".into(),
                ],
                values: vec![
                    SqlValue::Integer(3),
                    SqlValue::Text("Charlie".into()),
                    SqlValue::Integer(2),
                    SqlValue::Real(85000.0),
                    SqlValue::Text("2019-03-10".into()),
                ],
            },
            SqlOperation::Insert {
                table: "employees".into(),
                columns: vec![
                    "id".into(),
                    "name".into(),
                    "dept_id".into(),
                    "salary".into(),
                    "hired".into(),
                ],
                values: vec![
                    SqlValue::Integer(4),
                    SqlValue::Text("Diana".into()),
                    SqlValue::Null,
                    SqlValue::Real(110000.0),
                    SqlValue::Null,
                ],
            },
            SqlOperation::Commit,
            // JOIN + aggregate: average salary per department
            SqlOperation::Select {
                table: "employees".into(),
                columns: vec!["name".into()],
                where_clause: None,
                joins: vec![JoinClause {
                    join_type: JoinType::Left,
                    table: "departments".into(),
                    on_left_col: "dept_id".into(),
                    on_right_col: "id".into(),
                }],
                aggregates: vec![
                    agg(AggregateExprAggFunc::Avg, "salary"),
                    agg(AggregateExprAggFunc::Count, "id"),
                ],
                group_by: vec!["name".into()],
                order_by: vec![order_by("name", OrderDir::Asc)],
                limit: None,
            },
            // WHERE with range and LIKE combined
            SqlOperation::Select {
                table: "employees".into(),
                columns: vec!["id".into(), "name".into(), "salary".into()],
                where_clause: Some(Box::new(WhereClause::And {
                    left: Box::new(WhereClause::Gt {
                        col: "salary".into(),
                        val: SqlValue::Real(90000.0),
                    }),
                    right: Box::new(WhereClause::Like {
                        col: "name".into(),
                        pattern: "A%".into(),
                    }),
                })),
                joins: vec![],
                aggregates: vec![],
                group_by: vec![],
                order_by: vec![order_by("salary", OrderDir::Desc)],
                limit: Some(5),
            },
            // Update with conditions
            SqlOperation::Update {
                table: "employees".into(),
                assignments: vec![assign("salary", SqlValue::Real(100000.0))],
                where_clause: Some(Box::new(WhereClause::Lt {
                    col: "salary".into(),
                    val: SqlValue::Real(90000.0),
                })),
            },
            // Delete employee with NULL dept
            SqlOperation::Delete {
                table: "employees".into(),
                where_clause: Some(Box::new(WhereClause::IsNull {
                    col: "dept_id".into(),
                })),
            },
            SqlOperation::Vacuum,
        ],
    );

    // ── BETWEEN edge cases ──────────────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_between_edge",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(i64::MIN, "min"),
            insert_ab(-1, "neg"),
            insert_ab(0, "zero"),
            insert_ab(1, "pos"),
            insert_ab(i64::MAX, "max"),
            // Normal between
            select_ab_where(WhereClause::Between {
                col: "a".into(),
                low: SqlValue::Integer(-1),
                high: SqlValue::Integer(1),
            }),
            // Reversed bounds (low > high, should return nothing)
            select_ab_where(WhereClause::Between {
                col: "a".into(),
                low: SqlValue::Integer(1),
                high: SqlValue::Integer(-1),
            }),
            // Same low and high
            select_ab_where(WhereClause::Between {
                col: "a".into(),
                low: SqlValue::Integer(0),
                high: SqlValue::Integer(0),
            }),
            // Full i64 range
            select_ab_where(WhereClause::Between {
                col: "a".into(),
                low: SqlValue::Integer(i64::MIN),
                high: SqlValue::Integer(i64::MAX),
            }),
        ],
    );

    // ── InList edge cases ───────────────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_inlist_edge",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "a"),
            insert_ab(2, "b"),
            // Empty InList
            select_ab_where(WhereClause::InList {
                col: "a".into(),
                vals: vec![],
            }),
            // Single element
            select_ab_where(WhereClause::InList {
                col: "a".into(),
                vals: vec![SqlValue::Integer(1)],
            }),
            // Many elements
            select_ab_where(WhereClause::InList {
                col: "a".into(),
                vals: (0..200).map(SqlValue::Integer).collect(),
            }),
            // Mixed types in InList
            select_ab_where(WhereClause::InList {
                col: "a".into(),
                vals: vec![
                    SqlValue::Integer(1),
                    SqlValue::Text("2".into()),
                    SqlValue::Real(3.0),
                    SqlValue::Null,
                ],
            }),
        ],
    );

    // ── Update all rows / no WHERE ──────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_update_all",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "old"),
            insert_ab(2, "old"),
            insert_ab(3, "old"),
            // Update all rows (no WHERE)
            SqlOperation::Update {
                table: "t".into(),
                assignments: vec![assign("b", SqlValue::Text("new".into()))],
                where_clause: None,
            },
            select_from("t", vec!["a", "b"], None),
        ],
    );

    // ── Multiple operations on same column value ────────────────────────

    emit(
        &corpus_dir,
        "seed_insert_update_select_delete",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "v1"),
            SqlOperation::Update {
                table: "t".into(),
                assignments: vec![assign("b", SqlValue::Text("v2".into()))],
                where_clause: Some(Box::new(where_eq_int("a", 1))),
            },
            select_ab_where(where_eq_int("a", 1)),
            SqlOperation::Delete {
                table: "t".into(),
                where_clause: Some(Box::new(where_eq_int("a", 1))),
            },
            select_from("t", vec!["a", "b"], None),
        ],
    );

    // ── Vacuum on empty database (no tables) ────────────────────────────

    emit(
        &corpus_dir,
        "seed_vacuum_empty_db",
        &mut count,
        &vec![SqlOperation::Vacuum],
    );

    // ── Double vacuum ───────────────────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_double_vacuum",
        &mut count,
        &vec![
            create_ab_table(),
            insert_ab(1, "x"),
            SqlOperation::Vacuum,
            SqlOperation::Vacuum,
        ],
    );

    // ── Empty operation list ────────────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_empty_ops",
        &mut count,
        &Vec::<SqlOperation>::new(),
    );

    // ── Single no-op operations ─────────────────────────────────────────

    emit(
        &corpus_dir,
        "seed_just_begin",
        &mut count,
        &vec![SqlOperation::BeginTransaction],
    );
    emit(
        &corpus_dir,
        "seed_just_commit",
        &mut count,
        &vec![SqlOperation::Commit],
    );
    emit(
        &corpus_dir,
        "seed_just_rollback",
        &mut count,
        &vec![SqlOperation::Rollback],
    );
    emit(
        &corpus_dir,
        "seed_just_vacuum",
        &mut count,
        &vec![SqlOperation::Vacuum],
    );

    println!(
        "Generated {count} seed corpus files in {}",
        corpus_dir.display()
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn emit(dir: &std::path::Path, name: &str, count: &mut usize, ops: &Vec<SqlOperation>) {
    let data = Encode!(ops).unwrap();
    let path = dir.join(name);
    fs::write(&path, &data).unwrap();
    println!("  wrote {} ({} bytes)", path.display(), data.len());
    *count += 1;
}

fn col(
    name: &str,
    col_type: &str,
    primary_key: bool,
    not_null: bool,
    unique: bool,
    default_val: Option<SqlValue>,
) -> ColumnDef {
    ColumnDef {
        name: name.into(),
        col_type: col_type.into(),
        primary_key,
        not_null,
        unique,
        default_val,
    }
}

fn assign(col_name: &str, val: SqlValue) -> SqlOperationUpdateAssignmentsItem {
    SqlOperationUpdateAssignmentsItem {
        col: col_name.into(),
        val,
    }
}

fn agg(func: AggregateExprAggFunc, col_name: &str) -> AggregateExpr {
    AggregateExpr {
        agg_func: func,
        col: col_name.into(),
    }
}

fn order_by(col_name: &str, dir: OrderDir) -> SqlOperationSelectOrderByItem {
    SqlOperationSelectOrderByItem {
        col: col_name.into(),
        dir,
    }
}

fn where_eq_int(col_name: &str, val: i64) -> WhereClause {
    WhereClause::Eq {
        col: col_name.into(),
        val: SqlValue::Integer(val),
    }
}

fn where_eq_text(col_name: &str, val: &str) -> WhereClause {
    WhereClause::Eq {
        col: col_name.into(),
        val: SqlValue::Text(val.into()),
    }
}

// ── Table creation helpers ──────────────────────────────────────────────

fn create_ab_table() -> SqlOperation {
    SqlOperation::CreateTable {
        table: "t".into(),
        columns: vec![
            col("a", "INTEGER", true, false, false, None),
            col("b", "TEXT", false, false, false, None),
        ],
    }
}

fn create_kv_table() -> SqlOperation {
    SqlOperation::CreateTable {
        table: "kv".into(),
        columns: vec![
            col("k", "TEXT", true, false, false, None),
            col("v", "BLOB", false, false, false, None),
        ],
    }
}

fn create_items_table() -> SqlOperation {
    SqlOperation::CreateTable {
        table: "items".into(),
        columns: vec![
            col("id", "INTEGER", true, false, false, None),
            col("name", "TEXT", false, true, false, None),
            col("price", "REAL", false, false, false, None),
        ],
    }
}

fn create_sales_table() -> SqlOperation {
    SqlOperation::CreateTable {
        table: "sales".into(),
        columns: vec![
            col("region", "TEXT", false, true, false, None),
            col("amount", "REAL", false, false, false, None),
        ],
    }
}

// ── Insert helpers ──────────────────────────────────────────────────────

fn insert_ab(a: i64, b: &str) -> SqlOperation {
    SqlOperation::Insert {
        table: "t".into(),
        columns: vec!["a".into(), "b".into()],
        values: vec![SqlValue::Integer(a), SqlValue::Text(b.into())],
    }
}

fn insert_ab_nullable(a: SqlValue, b: SqlValue) -> SqlOperation {
    SqlOperation::Insert {
        table: "t".into(),
        columns: vec!["a".into(), "b".into()],
        values: vec![a, b],
    }
}

fn insert_item(id: i64, name: &str, price: f64) -> SqlOperation {
    SqlOperation::Insert {
        table: "items".into(),
        columns: vec!["id".into(), "name".into(), "price".into()],
        values: vec![
            SqlValue::Integer(id),
            SqlValue::Text(name.into()),
            SqlValue::Real(price),
        ],
    }
}

fn insert_kv(key: &str, val: &[u8]) -> SqlOperation {
    SqlOperation::Insert {
        table: "kv".into(),
        columns: vec!["k".into(), "v".into()],
        values: vec![
            SqlValue::Text(key.into()),
            SqlValue::Blob(val.to_vec().into()),
        ],
    }
}

fn insert_kv_text(key: &str, val: &str) -> SqlOperation {
    SqlOperation::Insert {
        table: "kv".into(),
        columns: vec!["k".into(), "v".into()],
        values: vec![
            SqlValue::Text(key.into()),
            SqlValue::Blob(val.as_bytes().to_vec().into()),
        ],
    }
}

fn insert_sale(region: &str, amount: f64) -> SqlOperation {
    SqlOperation::Insert {
        table: "sales".into(),
        columns: vec!["region".into(), "amount".into()],
        values: vec![SqlValue::Text(region.into()), SqlValue::Real(amount)],
    }
}

fn insert_sale_nullable(region: SqlValue, amount: SqlValue) -> SqlOperation {
    SqlOperation::Insert {
        table: "sales".into(),
        columns: vec!["region".into(), "amount".into()],
        values: vec![region, amount],
    }
}

fn insert_float(id: i64, v: f64) -> SqlOperation {
    SqlOperation::Insert {
        table: "floats".into(),
        columns: vec!["id".into(), "v".into()],
        values: vec![SqlValue::Integer(id), SqlValue::Real(v)],
    }
}

// ── Select helpers ──────────────────────────────────────────────────────

fn select_from(table: &str, cols: Vec<&str>, wc: Option<WhereClause>) -> SqlOperation {
    SqlOperation::Select {
        table: table.into(),
        columns: cols.into_iter().map(String::from).collect(),
        where_clause: wc.map(Box::new),
        joins: vec![],
        aggregates: vec![],
        group_by: vec![],
        order_by: vec![],
        limit: None,
    }
}

fn select_ab_where(wc: WhereClause) -> SqlOperation {
    select_from("t", vec!["a", "b"], Some(wc))
}

fn select_kv_like(pattern: &str) -> SqlOperation {
    select_from(
        "kv",
        vec!["k", "v"],
        Some(WhereClause::Like {
            col: "k".into(),
            pattern: pattern.into(),
        }),
    )
}

fn select_ordered(
    table: &str,
    cols: Vec<&str>,
    order_col: &str,
    dir: OrderDir,
    limit: Option<u32>,
) -> SqlOperation {
    SqlOperation::Select {
        table: table.into(),
        columns: cols.into_iter().map(String::from).collect(),
        where_clause: None,
        joins: vec![],
        aggregates: vec![],
        group_by: vec![],
        order_by: vec![order_by(order_col, dir)],
        limit,
    }
}

// ── WHERE clause generators ─────────────────────────────────────────────

fn deep_and_chain(depth: u32) -> WhereClause {
    if depth == 0 {
        return WhereClause::Eq {
            col: "a".into(),
            val: SqlValue::Integer(1),
        };
    }
    WhereClause::And {
        left: Box::new(WhereClause::Gt {
            col: "a".into(),
            val: SqlValue::Integer(-(depth as i64)),
        }),
        right: Box::new(deep_and_chain(depth - 1)),
    }
}

fn deep_or_chain(depth: u32) -> WhereClause {
    if depth == 0 {
        return WhereClause::Eq {
            col: "a".into(),
            val: SqlValue::Integer(1),
        };
    }
    WhereClause::Or {
        left: Box::new(WhereClause::Eq {
            col: "a".into(),
            val: SqlValue::Integer(depth as i64),
        }),
        right: Box::new(deep_or_chain(depth - 1)),
    }
}
