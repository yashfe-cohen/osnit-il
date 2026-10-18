"""Domain & infrastructure intelligence + recursive pivot expansion: the engine walks
person → domain → subdomains (crt.sh) / registrant (RDAP) → more people, and high-confidence newly
discovered identifiers feed focused extra discovery rounds (Maltego-style "a result of a result").
Precision-first: only a domain the target actually owns/uses is ever pivoted on — never free-mail or a
big platform — and a privacy-protected WHOIS registrant yields nothing."""
import asyncio
import json
import unittest

from osnit.web_osint import (SearchTargetProfile, check_certificate_transparency, check_rdap_domain,
                             collect_leads_from_findings, is_pivotable_domain, recon_entity_graph,
                             recursive_pivot_expand, registrable_domain, run_layer_domain_intel)


def _run(coro):
    return asyncio.run(coro)


class DomainReduction(unittest.TestCase):
    def test_registrable_domain_handles_emails_urls_and_il_suffixes(self):
        self.assertEqual(registrable_domain("a.b.example.co.il"), "example.co.il")
        self.assertEqual(registrable_domain("Foo@Example.COM"), "example.com")
        self.assertEqual(registrable_domain("https://sub.site.org.il/x?y=1"), "site.org.il")
        self.assertEqual(registrable_domain("notadomain"), "")

    def test_pivotable_rejects_freemail_platforms_and_bare_suffixes(self):
        self.assertFalse(is_pivotable_domain("gmail.com"))
        self.assertFalse(is_pivotable_domain("walla.co.il"))
        self.assertFalse(is_pivotable_domain("linkedin.com"))
        self.assertFalse(is_pivotable_domain("co.il"))
        self.assertTrue(is_pivotable_domain("acme.co.il"))
        self.assertTrue(is_pivotable_domain("danalevi.net"))


class ProfileSeeding(unittest.TestCase):
    def test_profile_seeds_only_pivotable_domains(self):
        p = SearchTargetProfile.from_raw(
            name="Dana Levi",
            emails=["dana@acme.co.il", "dana@gmail.com"],
            known_urls=["https://danalevi.net/about"],
        )
        self.assertIn("acme.co.il", p.domains)
        self.assertIn("danalevi.net", p.domains)
        self.assertNotIn("gmail.com", p.domains)
        self.assertEqual(sorted(p.pivotable_domains()), ["acme.co.il", "danalevi.net"])


_CRT = json.dumps([
    {"name_value": "www.acme.co.il\nmail.acme.co.il"},
    {"name_value": "*.vpn.acme.co.il"},
    {"name_value": "acme.co.il"},
])
_RDAP = json.dumps({
    "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [
            ["fn", {}, "text", "Dana Levi"], ["email", {}, "text", "dana@acme.co.il"],
            ["org", {}, "text", "Acme Ltd"]]]},
        {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy"]]]},
    ],
    "events": [{"eventAction": "registration", "eventDate": "2019-05-01T00:00:00Z"}],
})
_RDAP_PRIVATE = json.dumps({
    "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [
            ["fn", {}, "text", "REDACTED FOR PRIVACY"],
            ["email", {}, "text", "privacy@contactprivacy.com"]]]},
    ],
})


def _fetch(crt=_CRT, rdap=_RDAP):
    def fetch(url, headers):
        if "crt.sh" in url:
            return (200, crt.encode(), {"Content-Type": "application/json"})
        if "rdap" in url:
            return (200, rdap.encode(), {})
        return (0, b"", {})
    return fetch


class CertificateTransparency(unittest.TestCase):
    def test_crtsh_surfaces_subdomains_and_drops_apex_and_wildcards(self):
        f = _run(check_certificate_transparency("acme.co.il", http_fetcher=_fetch()))
        self.assertTrue(f)
        subs = f[0]["extracted_data"]["subdomains"]
        self.assertIn("mail.acme.co.il", subs)
        self.assertIn("vpn.acme.co.il", subs)          # '*.' stripped
        self.assertNotIn("acme.co.il", subs)           # apex dropped
        self.assertNotIn("www.acme.co.il", subs)       # www dropped

    def test_crtsh_never_runs_on_freemail(self):
        self.assertEqual(_run(check_certificate_transparency("gmail.com", http_fetcher=_fetch())), [])


class RDAPWhois(unittest.TestCase):
    def test_rdap_extracts_public_registrant(self):
        f = _run(check_rdap_domain("acme.co.il", http_fetcher=_fetch()))
        self.assertTrue(f)
        ed = f[0]["extracted_data"]
        self.assertEqual(ed["registrant_name"], "Dana Levi")
        self.assertEqual(ed["registrant_email"], "dana@acme.co.il")
        self.assertEqual(ed["registrar"], "GoDaddy")

    def test_rdap_suppresses_privacy_protected_registrant(self):
        self.assertEqual(
            _run(check_rdap_domain("acme.co.il", http_fetcher=_fetch(rdap=_RDAP_PRIVATE))), [])


class LeadsAndGraph(unittest.TestCase):
    def test_domain_intel_leads_and_graph_nodes(self):
        findings = _run(run_layer_domain_intel(["acme.co.il"], http_fetcher=_fetch()))
        self.assertTrue(any(f["source_tool"] == "crtsh" for f in findings))
        self.assertTrue(any(f["source_tool"] == "rdap" for f in findings))

        p = SearchTargetProfile.from_raw(name="Dana Levi", emails=["dana@acme.co.il"])
        leads = collect_leads_from_findings(findings, p)
        types = {ld["type"] for ld in leads}
        self.assertIn("domain", types)
        self.assertIn("person", types)                 # the registrant
        self.assertIn("Dana Levi", [ld["value"] for ld in leads if ld["type"] == "person"])

        g = recon_entity_graph(p, findings, leads, [])
        self.assertTrue(any(n["kind"] == "domain" for n in g["nodes"]))

    def test_every_discovered_email_implies_its_pivotable_domain(self):
        p = SearchTargetProfile.from_raw(name="X")
        leads = collect_leads_from_findings(
            [{"extracted_data": {"email": "worker@company.co.il"}, "confidence": 0.9,
              "source_tool": "github", "url": ""}], p)
        self.assertIn("company.co.il", [ld["value"] for ld in leads if ld["type"] == "domain"])


class RecursivePivot(unittest.TestCase):
    def test_a_new_domain_lead_triggers_an_extra_discovery_hop(self):
        p = SearchTargetProfile.from_raw(name="Dana Levi")
        seed = [{"type": "domain", "value": "acme.co.il", "confidence": 0.9, "source_tool": "rdap"}]
        new = _run(recursive_pivot_expand(p, [], seed, max_depth=2, http_fetcher=_fetch()))
        self.assertTrue(new, "the new domain lead did not trigger a pivot hop")
        self.assertTrue(all(f["extracted_data"].get("pivot_depth") == 2 for f in new))
        self.assertIn("acme.co.il", p.domains)         # folded into the profile for the graph/next hop

    def test_depth_1_does_no_expansion(self):
        p = SearchTargetProfile.from_raw(name="Dana Levi")
        seed = [{"type": "domain", "value": "acme.co.il", "confidence": 0.9, "source_tool": "rdap"}]
        self.assertEqual(_run(recursive_pivot_expand(p, [], seed, max_depth=1, http_fetcher=_fetch())), [])

    def test_low_confidence_identifiers_do_not_pivot_but_their_domain_does(self):
        # a below-floor email must not be re-enriched, yet its pivotable domain is still worth infra recon
        p = SearchTargetProfile.from_raw(name="Dana Levi")
        seed = [{"type": "email", "value": "maybe@acme.co.il", "confidence": 0.3, "source_tool": "scrape"}]
        new = _run(recursive_pivot_expand(p, [], seed, max_depth=2, http_fetcher=_fetch()))
        self.assertIn("acme.co.il", p.domains)
        self.assertTrue(any(f["source_tool"] in ("crtsh", "rdap") for f in new))


if __name__ == "__main__":
    unittest.main()
