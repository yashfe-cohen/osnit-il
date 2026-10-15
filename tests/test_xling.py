import unittest

from osnit.xling import name_matches_label, role_canon, same_org_name, same_person_name
from tests import helpers
from tests.helpers import PAGES


class XLing(unittest.TestCase):
    def test_names(self):
        self.assertTrue(same_person_name("יונתן חייט", "Jonathan Hayat"))
        self.assertTrue(same_person_name("יוגב פלדמן", "Yogev Feldman"))       # outside the dictionary: skeletons
        self.assertFalse(same_person_name("דנה כהן", "Dina Cohen"))            # dictionary says דנה = Dana
        self.assertFalse(same_person_name("יוגב פלדמן", "Yogev Fridman"))

    def test_orgs_and_roles(self):
        self.assertTrue(same_org_name("הטכניון", "Technion"))
        self.assertTrue(same_org_name("אינטל ישראל", "Intel Israel"))
        self.assertFalse(same_org_name("אלפא", "Alpha"))                       # 2 consonants alone: too ambiguous
        self.assertTrue(name_matches_label('אלפא בע"מ', "alpha"))
        self.assertTrue(name_matches_label("בנק הפועלים", "bankhapoalim"))
        self.assertFalse(name_matches_label("גמא", "alpha"))
        self.assertEqual(role_canon('מנכ"לית, אלפא'), role_canon("Chief Executive Officer"))


class MergeInProfile(unittest.TestCase):
    def setUp(self):
        PAGES.clear()
        PAGES["/he"] = ('<p>יונתן חייט, מנכ"ל חברת אלפא בע"מ, נאם בכנס.</p>', "text/html; charset=utf-8")
        PAGES["/en"] = ("<p>Jonathan Hayat, CEO of Alpha Ltd. Contact: jhayat@alpha.co.il</p>", "text/html")
        PAGES["/rel"] = ('<p>יונתן חייט וד\"ר רונית לוי השתתפו בפאנל.</p><p>Jonathan Hayat and Dr. Ronit Levi spoke.</p>',
                         "text/html; charset=utf-8")
        self.srv, self.base, self.store, self.eng, self.svc, _ = helpers.make(["/he", "/en", "/rel"])

    def tearDown(self):
        self.srv.shutdown()

    def test_one_identity_one_org_one_role_one_related_person(self):
        sid = self.svc.search("יונתן חייט")["subject_id"]
        self.eng.drain()
        p = self.svc.profile(sid)
        self.assertEqual(len(p["identities"]), 1)                 # Hebrew + English pages joined via the org
        ident = p["identities"][0]
        self.assertEqual(len(ident["orgs"]), 1)
        self.assertEqual(len(ident["orgs"][0]["aliases"]), 1)
        self.assertEqual(len(ident["roles"]), 1)
        self.assertEqual(ident["roles"][0]["sources"], 2)
        self.assertEqual(ident["roles"][0]["confidence"], 0.75)   # both pages on one host: not independent
        names = [r["value"] for r in p["related"]]
        self.assertEqual(len([n for n in names if "רונית" in n or "Ronit" in n]), 1)


if __name__ == "__main__":
    unittest.main()
