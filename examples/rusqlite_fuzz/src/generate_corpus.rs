//! Generates seed corpus files for the rusqlite fuzzer.
//! Run once: `cargo run --bin generate_corpus -p rusqlite_fuzz`

use candid::Encode;
use std::fs;
use std::path::PathBuf;

fn main() {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    fs::create_dir_all(&corpus_dir).unwrap();

    // Seed 1: Create a simple table
    let seed1 = Encode!(&vec![
        SqlOp::CreateTable {
            table: "users".to_string(),
            columns: vec![
                col("id", "INTEGER", true, false, false, None),
                col("name", "TEXT", false, true, false, None),
                col("email", "TEXT", false, false, true, None),
            ],
        },
    ])
    .unwrap();
    write_seed(&corpus_dir, "seed_create_table", &seed1);

    // Seed 2: Create table + insert
    let seed2 = Encode!(&vec![
        SqlOp::CreateTable {
            table: "items".to_string(),
            columns: vec![
                col("id", "INTEGER", true, false, false, None),
                col("name", "TEXT", false, true, false, None),
                col("price", "REAL", false, false, false, None),
            ],
        },
        SqlOp::Insert {
            table: "items".to_string(),
            columns: vec!["id".into(), "name".into(), "price".into()],
            values: vec![
                SqlVal::Integer(1),
                SqlVal::Text("Widget".into()),
                SqlVal::Real(9.99),
            ],
        },
        SqlOp::Insert {
            table: "items".to_string(),
            columns: vec!["id".into(), "name".into(), "price".into()],
            values: vec![
                SqlVal::Integer(2),
                SqlVal::Text("Gadget".into()),
                SqlVal::Real(19.99),
            ],
        },
    ])
    .unwrap();
    write_seed(&corpus_dir, "seed_insert", &seed2);

    // Seed 3: Select with WHERE
    let seed3 = Encode!(&vec![
        SqlOp::CreateTable {
            table: "t".to_string(),
            columns: vec![
                col("a", "INTEGER", true, false, false, None),
                col("b", "TEXT", false, false, false, None),
            ],
        },
        SqlOp::Insert {
            table: "t".to_string(),
            columns: vec!["a".into(), "b".into()],
            values: vec![SqlVal::Integer(42), SqlVal::Text("hello".into())],
        },
        SqlOp::Select {
            table: "t".to_string(),
            columns: vec!["a".into(), "b".into()],
            where_clause: Some(Where::Eq {
                col: "a".into(),
                val: SqlVal::Integer(42),
            }),
            joins: vec![],
            aggregates: vec![],
            group_by: vec![],
            order_by: vec![],
            limit: None,
        },
    ])
    .unwrap();
    write_seed(&corpus_dir, "seed_select_where", &seed3);

    // Seed 4: Update + Delete
    let seed4 = Encode!(&vec![
        SqlOp::CreateTable {
            table: "kv".to_string(),
            columns: vec![
                col("k", "TEXT", true, false, false, None),
                col("v", "BLOB", false, false, false, None),
            ],
        },
        SqlOp::Insert {
            table: "kv".to_string(),
            columns: vec!["k".into(), "v".into()],
            values: vec![
                SqlVal::Text("key1".into()),
                SqlVal::Blob(vec![1, 2, 3]),
            ],
        },
        SqlOp::Update {
            table: "kv".to_string(),
            assignments: vec![Assign {
                col: "v".into(),
                val: SqlVal::Blob(vec![4, 5, 6]),
            }],
            where_clause: Some(Where::Eq {
                col: "k".into(),
                val: SqlVal::Text("key1".into()),
            }),
        },
        SqlOp::Delete {
            table: "kv".to_string(),
            where_clause: Some(Where::Eq {
                col: "k".into(),
                val: SqlVal::Text("key1".into()),
            }),
        },
    ])
    .unwrap();
    write_seed(&corpus_dir, "seed_update_delete", &seed4);

    // Seed 5: Transaction + raw SQL
    let seed5 = Encode!(&vec![
        SqlOp::CreateTable {
            table: "tx_test".to_string(),
            columns: vec![col("x", "INTEGER", false, false, false, None)],
        },
        SqlOp::BeginTransaction,
        SqlOp::Insert {
            table: "tx_test".to_string(),
            columns: vec!["x".into()],
            values: vec![SqlVal::Integer(100)],
        },
        SqlOp::Commit,
        SqlOp::RawSql {
            sql: "SELECT COUNT(*) FROM tx_test".to_string(),
        },
    ])
    .unwrap();
    write_seed(&corpus_dir, "seed_transaction", &seed5);

    // Seed 6: Two tables + JOIN
    let seed6 = Encode!(&vec![
        SqlOp::CreateTable {
            table: "orders".to_string(),
            columns: vec![
                col("id", "INTEGER", true, false, false, None),
                col("customer_id", "INTEGER", false, true, false, None),
                col("amount", "REAL", false, false, false, None),
            ],
        },
        SqlOp::CreateTable {
            table: "customers".to_string(),
            columns: vec![
                col("id", "INTEGER", true, false, false, None),
                col("name", "TEXT", false, true, false, None),
            ],
        },
        SqlOp::Insert {
            table: "customers".to_string(),
            columns: vec!["id".into(), "name".into()],
            values: vec![SqlVal::Integer(1), SqlVal::Text("Alice".into())],
        },
        SqlOp::Insert {
            table: "orders".to_string(),
            columns: vec!["id".into(), "customer_id".into(), "amount".into()],
            values: vec![SqlVal::Integer(1), SqlVal::Integer(1), SqlVal::Real(50.0)],
        },
        SqlOp::Select {
            table: "orders".to_string(),
            columns: vec!["name".into(), "amount".into()],
            where_clause: None,
            joins: vec![Join {
                join_type: JoinTy::Inner,
                table: "customers".into(),
                on_left_col: "customer_id".into(),
                on_right_col: "id".into(),
            }],
            aggregates: vec![],
            group_by: vec![],
            order_by: vec![],
            limit: None,
        },
    ])
    .unwrap();
    write_seed(&corpus_dir, "seed_join", &seed6);

    // Seed 7: Aggregates + GROUP BY
    let seed7 = Encode!(&vec![
        SqlOp::CreateTable {
            table: "sales".to_string(),
            columns: vec![
                col("region", "TEXT", false, true, false, None),
                col("amount", "REAL", false, false, false, None),
            ],
        },
        SqlOp::Insert {
            table: "sales".to_string(),
            columns: vec!["region".into(), "amount".into()],
            values: vec![SqlVal::Text("east".into()), SqlVal::Real(100.0)],
        },
        SqlOp::Insert {
            table: "sales".to_string(),
            columns: vec!["region".into(), "amount".into()],
            values: vec![SqlVal::Text("west".into()), SqlVal::Real(200.0)],
        },
        SqlOp::Insert {
            table: "sales".to_string(),
            columns: vec!["region".into(), "amount".into()],
            values: vec![SqlVal::Text("east".into()), SqlVal::Real(150.0)],
        },
        SqlOp::Select {
            table: "sales".to_string(),
            columns: vec!["region".into()],
            where_clause: None,
            joins: vec![],
            aggregates: vec![
                Agg {
                    func: AggFn::Sum,
                    col: "amount".into(),
                },
                Agg {
                    func: AggFn::Count,
                    col: "amount".into(),
                },
            ],
            group_by: vec!["region".into()],
            order_by: vec![OrdBy {
                col: "region".into(),
                dir: Dir::Asc,
            }],
            limit: Some(10),
        },
    ])
    .unwrap();
    write_seed(&corpus_dir, "seed_aggregate", &seed7);

    // Seed 8: Index + Vacuum
    let seed8 = Encode!(&vec![
        SqlOp::CreateTable {
            table: "indexed".to_string(),
            columns: vec![
                col("id", "INTEGER", true, false, false, None),
                col("val", "TEXT", false, false, false, None),
            ],
        },
        SqlOp::CreateIndex {
            table: "indexed".to_string(),
            columns: vec!["val".into()],
            unique: false,
        },
        SqlOp::Vacuum,
    ])
    .unwrap();
    write_seed(&corpus_dir, "seed_index_vacuum", &seed8);

    println!("Generated seed corpus in {}", corpus_dir.display());
}

fn write_seed(dir: &std::path::Path, name: &str, data: &[u8]) {
    let path = dir.join(name);
    fs::write(&path, data).unwrap();
    println!("  wrote {} ({} bytes)", path.display(), data.len());
}

// ---- Minimal Candid-compatible types for encoding seeds ----
// These must match the canister's Candid interface exactly.

use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Serialize, Deserialize)]
enum SqlVal {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(CandidType, Serialize, Deserialize)]
struct ColDef {
    name: String,
    col_type: String,
    primary_key: bool,
    not_null: bool,
    unique: bool,
    default_val: Option<SqlVal>,
}

fn col(
    name: &str,
    col_type: &str,
    primary_key: bool,
    not_null: bool,
    unique: bool,
    default_val: Option<SqlVal>,
) -> ColDef {
    ColDef {
        name: name.to_string(),
        col_type: col_type.to_string(),
        primary_key,
        not_null,
        unique,
        default_val,
    }
}

#[derive(CandidType, Serialize, Deserialize)]
enum Where {
    Eq { col: String, val: SqlVal },
    NotEq { col: String, val: SqlVal },
    Lt { col: String, val: SqlVal },
    Gt { col: String, val: SqlVal },
    IsNull { col: String },
    Like { col: String, pattern: String },
    Between { col: String, low: SqlVal, high: SqlVal },
    InList { col: String, vals: Vec<SqlVal> },
    And { left: Box<Where>, right: Box<Where> },
    Or { left: Box<Where>, right: Box<Where> },
}

#[derive(CandidType, Serialize, Deserialize)]
enum JoinTy {
    Inner,
    Left,
    Cross,
}

#[derive(CandidType, Serialize, Deserialize)]
struct Join {
    join_type: JoinTy,
    table: String,
    on_left_col: String,
    on_right_col: String,
}

#[derive(CandidType, Serialize, Deserialize)]
enum AggFn {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    GroupConcat,
}

#[derive(CandidType, Serialize, Deserialize)]
struct Agg {
    func: AggFn,
    col: String,
}

#[derive(CandidType, Serialize, Deserialize)]
enum Dir {
    Asc,
    Desc,
}

#[derive(CandidType, Serialize, Deserialize)]
struct OrdBy {
    col: String,
    dir: Dir,
}

#[derive(CandidType, Serialize, Deserialize)]
struct Assign {
    col: String,
    val: SqlVal,
}

#[derive(CandidType, Serialize, Deserialize)]
enum SqlOp {
    CreateTable {
        table: String,
        columns: Vec<ColDef>,
    },
    DropTable {
        table: String,
    },
    Insert {
        table: String,
        columns: Vec<String>,
        values: Vec<SqlVal>,
    },
    Select {
        table: String,
        columns: Vec<String>,
        where_clause: Option<Where>,
        joins: Vec<Join>,
        aggregates: Vec<Agg>,
        group_by: Vec<String>,
        order_by: Vec<OrdBy>,
        limit: Option<u32>,
    },
    Update {
        table: String,
        assignments: Vec<Assign>,
        where_clause: Option<Where>,
    },
    Delete {
        table: String,
        where_clause: Option<Where>,
    },
    CreateIndex {
        table: String,
        columns: Vec<String>,
        unique: bool,
    },
    BeginTransaction,
    Commit,
    Rollback,
    Vacuum,
    RawSql {
        sql: String,
    },
}
