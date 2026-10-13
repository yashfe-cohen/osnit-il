"""
Unit tests for Phase 5 (UPGRADE_PLAN v2.0):
SQL State-Machine Parser, Deep Cell Unpacking, Key-Value Pivot, 3-Point Seek Sampling, and Content Overrides.
"""
import os
import shutil
import tempfile
import unittest

from osnit.analyze import analyze_file
from osnit.catalog import plan_columns
from osnit.sql_parser import (
    SQLStateMachineParser,
    parse_php_serialized,
    read_sql_dump,
    stream_sql_dump,
    unpack_cell_value,
    unpack_row_cells,
)
from osnit.store import Store


class TestSQLParserV2(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="osnit_sql_")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.store = Store(self.db_path)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # 1. State-Machine Schema Binding & Dialects
    # ------------------------------------------------------------------

    def test_create_table_to_insert_column_binding(self):
        """INSERT without explicit column names automatically uses columns from CREATE TABLE."""
        sql = """
        CREATE TABLE `users` (
            `id` int(11) NOT NULL AUTO_INCREMENT,
            `username` varchar(50) NOT NULL,
            `email` varchar(100) NOT NULL,
            PRIMARY KEY (`id`)
        );
        -- Hundreds of lines later...
        INSERT INTO `users` VALUES (1, 'yossi', 'yossi@example.com'), (2, 'dana', 'dana@test.org');
        """
        tables = list(read_sql_dump(sql, pivot_meta=False, unpack_cells=False))
        self.assertEqual(len(tables), 1)
        name, cols, rows = tables[0]
        self.assertEqual(name, "users")
        self.assertEqual(cols, ["id", "username", "email"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["username"], "yossi")
        self.assertEqual(rows[0]["email"], "yossi@example.com")
        self.assertEqual(rows[1]["username"], "dana")

    def test_postgres_copy_format(self):
        r"""Supports PostgreSQL COPY table (cols) FROM stdin; ... \."""
        sql = """
        CREATE TABLE customers (
            id integer,
            name text,
            phone text
        );
        COPY customers (id, name, phone) FROM stdin;
        101\tדוד כהן\t0501234567
        102\tרחל לוי\t\\N
        \\.
        """
        tables = list(read_sql_dump(sql, pivot_meta=False, unpack_cells=False))
        self.assertEqual(len(tables), 1)
        name, cols, rows = tables[0]
        self.assertEqual(name, "customers")
        self.assertEqual(cols, ["id", "name", "phone"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["name"], "דוד כהן")
        self.assertEqual(rows[0]["phone"], "0501234567")
        self.assertIsNone(rows[1]["phone"])

    def test_sql_server_bracket_dialect_and_hex(self):
        """Supports SQL Server [dbo].[table] and Hex string decoding."""
        sql = """
        CREATE TABLE [dbo].[audit_log] (
            [id] int,
            [actor] nvarchar(50),
            [token] varchar(100)
        );
        INSERT INTO [dbo].[audit_log] VALUES (1, 'admin', 0x61646d696e);
        """
        tables = list(read_sql_dump(sql, pivot_meta=False, unpack_cells=False))
        self.assertEqual(len(tables), 1)
        name, cols, rows = tables[0]
        self.assertEqual(name, "audit_log")
        self.assertEqual(rows[0]["token"], "admin")

    # ------------------------------------------------------------------
    # 2. Deep Cell Unpacking
    # ------------------------------------------------------------------

    def test_php_unserialize_hebrew_and_nested(self):
        """PHP serialized array with Hebrew characters is correctly parsed and flattened."""
        # a:2:{s:4:"name";s:8:"ישראל";s:5:"phone";s:10:"0501234567";}
        # Note: 'ישראל' is 5 Hebrew chars = 10 UTF-8 bytes. PHP serialize handles length.
        hebrew_text = "ישראל"
        raw_php = f'a:2:{{s:4:"name";s:10:"{hebrew_text}";s:5:"phone";s:10:"0501234567";}}'
        parsed, _ = parse_php_serialized(raw_php)
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed["name"], hebrew_text)
        self.assertEqual(parsed["phone"], "0501234567")

        # Test unpack_cell_value
        unpacked = unpack_cell_value(raw_php)
        self.assertIsNotNone(unpacked)
        self.assertEqual(unpacked["phone"], "0501234567")

    def test_json_and_query_string_cell_unpacking(self):
        """Unpacks JSON and query-string cells into virtual row columns."""
        row = {
            "id": "1",
            "metadata": '{"city": "חיפה", "coords": {"lat": 32.8, "lng": 34.9}}',
            "order_params": "billing_phone=0529876543&billing_id=012345678",
        }
        enriched = unpack_row_cells(row)
        self.assertEqual(enriched["metadata.city"], "חיפה")
        self.assertEqual(enriched["metadata.coords.lat"], 32.8)
        self.assertEqual(enriched["order_params.billing_phone"], "0529876543")
        self.assertEqual(enriched["order_params.billing_id"], "012345678")

    # ------------------------------------------------------------------
    # 3. Key-Value Pivot (wp_usermeta)
    # ------------------------------------------------------------------

    def test_wp_usermeta_table_pivot(self):
        """Tables with (user_id, meta_key, meta_value) automatically pivot into unified user records."""
        sql = """
        CREATE TABLE `wp_usermeta` (
            `umeta_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            `user_id` bigint(20) unsigned NOT NULL DEFAULT '0',
            `meta_key` varchar(255) DEFAULT NULL,
            `meta_value` longtext,
            PRIMARY KEY (`umeta_id`)
        );
        INSERT INTO `wp_usermeta` (`umeta_id`, `user_id`, `meta_key`, `meta_value`) VALUES
        (1, 50, 'first_name', 'דנה'),
        (2, 50, 'last_name', 'כהן'),
        (3, 50, 'billing_phone', '0541112233'),
        (4, 51, 'first_name', 'אבי'),
        (5, 51, 'billing_phone', '0524445566');
        """
        tables = list(read_sql_dump(sql, pivot_meta=True, unpack_cells=True))
        self.assertEqual(len(tables), 1)
        name, cols, rows = tables[0]
        self.assertEqual(name, "wp_usermeta")
        self.assertEqual(len(rows), 2)

        user_50 = next(r for r in rows if r.get("user_id") == "50")
        self.assertEqual(user_50["first_name"], "דנה")
        self.assertEqual(user_50["last_name"], "כהן")
        self.assertEqual(user_50["billing_phone"], "0541112233")

        user_51 = next(r for r in rows if r.get("user_id") == "51")
        self.assertEqual(user_51["first_name"], "אבי")
        self.assertEqual(user_51["billing_phone"], "0524445566")

    # ------------------------------------------------------------------
    # 4. Content Overrides Misleading Header (>= 40% Israeli ID / Phone)
    # ------------------------------------------------------------------

    def test_content_overrules_misleading_header(self):
        """A column named 'company' or 'varchar_1' with > 40% valid Israeli IDs or phones is classified by content."""
        # 1. Misleading 'company' header filled with valid Israeli IDs
        cols = ["company"]
        sample_rows = [
            {"company": "100000009"},  # valid ID
            {"company": "100000017"},  # valid ID
            {"company": "100000025"},  # valid ID
            {"company": "Acme Corp"},
            {"company": "Google"},
        ]
        plan = plan_columns(cols, sample_rows)
        col = plan.columns[0]
        self.assertEqual(col.type, "national_id")
        self.assertEqual(col.status, "entity")

        # 2. Misleading 'fax' header filled with mobile phones
        cols2 = ["fax"]
        sample_rows2 = [
            {"fax": "052-1234567"},
            {"fax": "054-9876543"},
            {"fax": "050-5555555"},
            {"fax": "N/A"},
            {"fax": ""},
        ]
        plan2 = plan_columns(cols2, sample_rows2)
        col2 = plan2.columns[0]
        self.assertEqual(col2.type, "phone")
        self.assertEqual(col2.status, "entity")

    # ------------------------------------------------------------------
    # 5. 3-Point Seek Sampling
    # ------------------------------------------------------------------

    def test_stream_sql_dump_file_and_seek_sampling(self):
        """stream_sql_dump streams statements from disk without errors."""
        sql_file = os.path.join(self.tmpdir, "large_dump.sql")
        with open(sql_file, "w", encoding="utf-8") as f:
            f.write("""
            CREATE TABLE `orders` (`order_id` int, `customer` text, `phone` text);
            INSERT INTO `orders` VALUES (1, 'User 1', '0501111111');
            INSERT INTO `orders` VALUES (2, 'User 2', '0502222222');
            """)

        results = {}
        for name, cols, rows_gen in stream_sql_dump(sql_file, encoding="utf-8", pivot_meta=False, unpack_cells=True):
            results[name] = (cols, list(rows_gen))

        self.assertIn("orders", results)
        cols, rows = results["orders"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["customer"], "User 1")


if __name__ == "__main__":
    unittest.main()
