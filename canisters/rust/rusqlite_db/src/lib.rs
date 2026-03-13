use arbitrary::Arbitrary;
use candid::{CandidType, Decode};
use ic_rusqlite::Connection;
use serde::{Deserialize, Serialize};

// ---- Candid types matching service.did ----

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
enum SqlValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
struct ColumnDef {
    name: String,
    col_type: String,
    primary_key: bool,
    not_null: bool,
    unique: bool,
    default_val: Option<SqlValue>,
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
enum WhereClause {
    Eq { col: String, val: SqlValue },
    NotEq { col: String, val: SqlValue },
    Lt { col: String, val: SqlValue },
    Gt { col: String, val: SqlValue },
    IsNull { col: String },
    Like { col: String, pattern: String },
    Between { col: String, low: SqlValue, high: SqlValue },
    InList { col: String, vals: Vec<SqlValue> },
    And { left: Box<WhereClause>, right: Box<WhereClause> },
    Or { left: Box<WhereClause>, right: Box<WhereClause> },
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
enum JoinType {
    Inner,
    Left,
    Cross,
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
struct JoinClause {
    join_type: JoinType,
    table: String,
    on_left_col: String,
    on_right_col: String,
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
enum AggregateFunc {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    GroupConcat,
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
struct AggregateExpr {
    agg_func: AggregateFunc,
    col: String,
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
enum OrderDir {
    Asc,
    Desc,
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
struct OrderByExpr {
    col: String,
    dir: OrderDir,
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
struct Assignment {
    col: String,
    val: SqlValue,
}

#[derive(Clone, Debug, Arbitrary, Deserialize, Serialize, CandidType)]
enum SqlOperation {
    CreateTable {
        table: String,
        columns: Vec<ColumnDef>,
    },
    DropTable {
        table: String,
    },
    Insert {
        table: String,
        columns: Vec<String>,
        values: Vec<SqlValue>,
    },
    Select {
        table: String,
        columns: Vec<String>,
        where_clause: Option<WhereClause>,
        joins: Vec<JoinClause>,
        aggregates: Vec<AggregateExpr>,
        group_by: Vec<String>,
        order_by: Vec<OrderByExpr>,
        limit: Option<u32>,
    },
    Update {
        table: String,
        assignments: Vec<Assignment>,
        where_clause: Option<WhereClause>,
    },
    Delete {
        table: String,
        where_clause: Option<WhereClause>,
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

// ---- SQL rendering helpers ----

/// Quote an identifier with double-quotes (intentionally not parameterized to stress identifier handling).
fn quote_ident(s: &str) -> String {
    // Truncate long identifiers to prevent excessive memory use
    let s = &s[..s.floor_char_boundary(128)];
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Render a SqlValue into a SQL literal string for direct embedding.
/// For parameterized queries we use `?` placeholders, but we need this for some contexts.
fn sql_value_to_param(val: &SqlValue) -> String {
    match val {
        SqlValue::Null => "NULL".to_string(),
        SqlValue::Integer(i) => i.to_string(),
        SqlValue::Real(f) => format!("{f}"),
        SqlValue::Text(s) => {
            let s = &s[..s.floor_char_boundary(1024)];
            format!("'{}'", s.replace('\'', "''"))
        }
        SqlValue::Blob(b) => {
            let b = if b.len() > 1024 { &b[..1024] } else { b.as_slice() };
            format!("X'{}'", b.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
        }
    }
}

const MAX_WHERE_DEPTH: usize = 10;

fn render_where(clause: &WhereClause, depth: usize) -> String {
    if depth > MAX_WHERE_DEPTH {
        return "1=1".to_string();
    }
    match clause {
        WhereClause::Eq { col, val } => {
            format!("{} = {}", quote_ident(col), sql_value_to_param(val))
        }
        WhereClause::NotEq { col, val } => {
            format!("{} != {}", quote_ident(col), sql_value_to_param(val))
        }
        WhereClause::Lt { col, val } => {
            format!("{} < {}", quote_ident(col), sql_value_to_param(val))
        }
        WhereClause::Gt { col, val } => {
            format!("{} > {}", quote_ident(col), sql_value_to_param(val))
        }
        WhereClause::IsNull { col } => {
            format!("{} IS NULL", quote_ident(col))
        }
        WhereClause::Like { col, pattern } => {
            let p = &pattern[..pattern.floor_char_boundary(256)];
            format!("{} LIKE '{}'", quote_ident(col), p.replace('\'', "''"))
        }
        WhereClause::Between { col, low, high } => {
            format!(
                "{} BETWEEN {} AND {}",
                quote_ident(col),
                sql_value_to_param(low),
                sql_value_to_param(high)
            )
        }
        WhereClause::InList { col, vals } => {
            let items: Vec<String> = vals.iter().take(64).map(sql_value_to_param).collect();
            if items.is_empty() {
                format!("{} IN (NULL)", quote_ident(col))
            } else {
                format!("{} IN ({})", quote_ident(col), items.join(", "))
            }
        }
        WhereClause::And { left, right } => {
            format!(
                "({}) AND ({})",
                render_where(left, depth + 1),
                render_where(right, depth + 1)
            )
        }
        WhereClause::Or { left, right } => {
            format!(
                "({}) OR ({})",
                render_where(left, depth + 1),
                render_where(right, depth + 1)
            )
        }
    }
}

fn execute_op(conn: &Connection, op: &SqlOperation) {
    match op {
        SqlOperation::CreateTable { table, columns } => {
            if columns.is_empty() {
                return;
            }
            let cols: Vec<String> = columns
                .iter()
                .take(32)
                .map(|c| {
                    let mut def = format!("{} {}", quote_ident(&c.name), quote_ident(&c.col_type));
                    if c.primary_key {
                        def.push_str(" PRIMARY KEY");
                    }
                    if c.not_null {
                        def.push_str(" NOT NULL");
                    }
                    if c.unique {
                        def.push_str(" UNIQUE");
                    }
                    if let Some(d) = &c.default_val {
                        def.push_str(&format!(" DEFAULT {}", sql_value_to_param(d)));
                    }
                    def
                })
                .collect();
            let sql = format!(
                "CREATE TABLE IF NOT EXISTS {} ({})",
                quote_ident(table),
                cols.join(", ")
            );
            let _ = conn.execute(&sql, []);
        }

        SqlOperation::DropTable { table } => {
            let sql = format!("DROP TABLE IF EXISTS {}", quote_ident(table));
            let _ = conn.execute(&sql, []);
        }

        SqlOperation::Insert {
            table,
            columns,
            values,
        } => {
            if columns.is_empty() || values.is_empty() {
                return;
            }
            let cols: Vec<String> = columns.iter().take(32).map(|c| quote_ident(c)).collect();
            let vals: Vec<String> = values.iter().take(32).map(sql_value_to_param).collect();
            // Pad or truncate values to match columns
            let val_count = cols.len();
            let mut final_vals = vals;
            final_vals.truncate(val_count);
            while final_vals.len() < val_count {
                final_vals.push("NULL".to_string());
            }
            let sql = format!(
                "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                quote_ident(table),
                cols.join(", "),
                final_vals.join(", ")
            );
            let _ = conn.execute(&sql, []);
        }

        SqlOperation::Select {
            table,
            columns,
            where_clause,
            joins,
            aggregates,
            group_by,
            order_by,
            limit,
        } => {
            // Build SELECT columns
            let mut select_parts: Vec<String> = Vec::new();
            for col in columns.iter().take(16) {
                select_parts.push(quote_ident(col));
            }
            for agg in aggregates.iter().take(8) {
                let func_name = match agg.agg_func {
                    AggregateFunc::Count => "COUNT",
                    AggregateFunc::Sum => "SUM",
                    AggregateFunc::Avg => "AVG",
                    AggregateFunc::Min => "MIN",
                    AggregateFunc::Max => "MAX",
                    AggregateFunc::GroupConcat => "GROUP_CONCAT",
                };
                select_parts.push(format!("{}({})", func_name, quote_ident(&agg.col)));
            }
            if select_parts.is_empty() {
                select_parts.push("*".to_string());
            }

            let mut sql = format!(
                "SELECT {} FROM {}",
                select_parts.join(", "),
                quote_ident(table)
            );

            // JOINs
            for join in joins.iter().take(4) {
                let join_kw = match join.join_type {
                    JoinType::Inner => "INNER JOIN",
                    JoinType::Left => "LEFT JOIN",
                    JoinType::Cross => "CROSS JOIN",
                };
                sql.push_str(&format!(
                    " {} {} ON {} = {}",
                    join_kw,
                    quote_ident(&join.table),
                    quote_ident(&join.on_left_col),
                    quote_ident(&join.on_right_col)
                ));
            }

            // WHERE
            if let Some(wc) = where_clause {
                sql.push_str(&format!(" WHERE {}", render_where(wc, 0)));
            }

            // GROUP BY
            if !group_by.is_empty() {
                let gb: Vec<String> = group_by.iter().take(8).map(|c| quote_ident(c)).collect();
                sql.push_str(&format!(" GROUP BY {}", gb.join(", ")));
            }

            // ORDER BY
            if !order_by.is_empty() {
                let ob: Vec<String> = order_by
                    .iter()
                    .take(8)
                    .map(|o| {
                        let dir = match o.dir {
                            OrderDir::Asc => "ASC",
                            OrderDir::Desc => "DESC",
                        };
                        format!("{} {dir}", quote_ident(&o.col))
                    })
                    .collect();
                sql.push_str(&format!(" ORDER BY {}", ob.join(", ")));
            }

            // LIMIT
            if let Some(lim) = limit {
                sql.push_str(&format!(" LIMIT {lim}"));
            }

            // Execute and consume results
            if let Ok(mut stmt) = conn.prepare(&sql) {
                let _ = stmt.query_map([], |_row| Ok(())).map(|rows| {
                    for _ in rows.take(1000) {}
                });
            }
        }

        SqlOperation::Update {
            table,
            assignments,
            where_clause,
        } => {
            if assignments.is_empty() {
                return;
            }
            let sets: Vec<String> = assignments
                .iter()
                .take(32)
                .map(|a| format!("{} = {}", quote_ident(&a.col), sql_value_to_param(&a.val)))
                .collect();
            let mut sql = format!(
                "UPDATE {} SET {}",
                quote_ident(table),
                sets.join(", ")
            );
            if let Some(wc) = where_clause {
                sql.push_str(&format!(" WHERE {}", render_where(wc, 0)));
            }
            let _ = conn.execute(&sql, []);
        }

        SqlOperation::Delete {
            table,
            where_clause,
        } => {
            let mut sql = format!("DELETE FROM {}", quote_ident(table));
            if let Some(wc) = where_clause {
                sql.push_str(&format!(" WHERE {}", render_where(wc, 0)));
            }
            let _ = conn.execute(&sql, []);
        }

        SqlOperation::CreateIndex {
            table,
            columns,
            unique,
        } => {
            if columns.is_empty() {
                return;
            }
            let cols: Vec<String> = columns.iter().take(16).map(|c| quote_ident(c)).collect();
            let idx_name = format!(
                "idx_{}_{}",
                table.chars().take(32).collect::<String>(),
                columns.first().map(|c| c.chars().take(16).collect::<String>()).unwrap_or_default()
            );
            let unique_kw = if *unique { "UNIQUE " } else { "" };
            let sql = format!(
                "CREATE {unique_kw}INDEX IF NOT EXISTS {} ON {} ({})",
                quote_ident(&idx_name),
                quote_ident(table),
                cols.join(", ")
            );
            let _ = conn.execute(&sql, []);
        }

        SqlOperation::BeginTransaction => {
            let _ = conn.execute("BEGIN TRANSACTION", []);
        }

        SqlOperation::Commit => {
            let _ = conn.execute("COMMIT", []);
        }

        SqlOperation::Rollback => {
            let _ = conn.execute("ROLLBACK", []);
        }

        SqlOperation::Vacuum => {
            let _ = conn.execute("VACUUM", []);
        }

        SqlOperation::RawSql { sql } => {
            // Truncate to prevent extremely large SQL strings
            let sql = &sql[..sql.floor_char_boundary(4096)];
            let _ = conn.execute_batch(sql);
        }
    }
}

#[unsafe(export_name = "canister_update sql_ops")]
pub fn sql_ops() {
    let ops = Decode!(&ic_cdk::api::msg_arg_data(), Vec<SqlOperation>).unwrap_or_default();

    ic_rusqlite::with_connection(|conn| {
        for op in &ops {
            execute_op(&conn, op);
        }
    });

    ic_cdk::api::msg_reply([]);
}
