import json
import unittest
import urllib.request

from osnit.contacts import contacts, contacts_csv
from osnit.importdb import import_db
from osnit.server import make_server, serve_in_thread
from tests import helpers


class Contacts(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make([])
        import tempfile, os
        p = os.path.join(tempfile.mkdtemp(), "c.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write(json.dumps({"name": "יונתן חייט", "email": "yon@alpha.co.il", "phone": "050-8317945", "company": "אלפא"}) + "\n")
            f.write(json.dumps({"name": "דנה לוי", "email": "dana@gamma.co.il"}) + "\n")
            f.write(json.dumps({"name": "משה כהן"}) + "\n")  # no contact
        import_db(self.eng, p, label="x")
        self.api = make_server(self.svc, "127.0.0.1", 0)
        serve_in_thread(self.api)
        self.url = f"http://127.0.0.1:{self.api.server_address[1]}"

    def tearDown(self):
        self.api.shutdown()
        self.srv.shutdown()

    def test_rows_aggregate_per_person(self):
        d = contacts(self.store)
        by = {r["name"]: r for r in d["rows"]}
        self.assertEqual(d["total"], 3)
        self.assertEqual(by["יונתן חייט"]["emails"], ["yon@alpha.co.il"])
        self.assertEqual(by["יונתן חייט"]["phones"], ["+972508317945"])
        self.assertTrue(by["יונתן חייט"]["orgs"])

    def test_only_contactable_filter(self):
        d = contacts(self.store, only_contactable=True)
        self.assertEqual({r["name"] for r in d["rows"]}, {"יונתן חייט", "דנה לוי"})

    def test_endpoint_and_csv(self):
        d = json.loads(urllib.request.urlopen(self.url + "/api/contacts").read())
        self.assertEqual(d["total"], 3)
        csv = urllib.request.urlopen(self.url + "/api/contacts/export").read().decode("utf-8")
        self.assertTrue(csv.startswith("﻿name,emails,phones,orgs,sources"))
        self.assertIn("yon@alpha.co.il", csv)
