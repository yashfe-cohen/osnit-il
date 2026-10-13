"""
Read a SQL dump (mysqldump / pg_dump / sqlite .dump) as tables of rows, without a database engine.

This module re-exports the v2.0 state-machine SQL parser from osnit.sql_parser for full backward compatibility.
"""
from .sql_parser import (
    SQLStateMachineParser,
    columns_from_create,
    detect_key_value_table,
    flatten_nested,
    parse_php_serialized,
    pivot_key_value_rows,
    read_sql_dump,
    split_fields,
    split_tuples,
    stream_sql_dump,
    unpack_cell_value,
    unpack_row_cells,
)

# For backward compatibility with tests/helpers expecting private helpers
_split_fields = split_fields
_split_tuples = split_tuples
_columns_from_create = columns_from_create
