"""Tests for the scoring semantics in run_eval.py (stdlib unittest; no stack needed).

Run:  python3 -m unittest eval/test_run_eval.py    (or: python3 eval/test_run_eval.py)

Each case here is one the first version of the harness got wrong -- most importantly, an extra wrong
answer next to the right one scored "correct", so the confidently-wrong gate could never fire.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_eval as ev  # noqa: E402

KEY = {
    "victim": {"ip": "172.16.1.66", "mac": "00:1e:64:ec:f3:08", "hostname": "DESKTOP-SKBR25F"},
    "user": {"account": "ccollier", "real_name": "Clark Collier"},
    "malware": {"family": "STRRAT"},
    "c2": [{"ip": "141.98.10.79"}],
}


def ans(question, **attrs):
    return {"question": question, "attributes": attrs}


def good_answers():
    return [
        ans("victim", host="172.16.1.66"),
        ans("signed-in-user", host="172.16.1.66", user="ccollier"),
        ans("malware", family="STRRAT"),
        ans("c2", address="141.98.10.79"),
    ]


def board(mac="00:1e:64:ec:f3:08", hostname="DESKTOP-SKBR25F.local"):
    return {"entities": [
        {"type": "HOST", "key": "172.16.1.66", "attributes": {"mac": mac, "hostname": hostname}},
        {"type": "USER", "key": "ccollier", "attributes": {}},
    ]}


def status(results, field):
    return next(r["status"] for r in results if r["field"] == field)


def detail(results, field):
    return next(r["detail"] for r in results if r["field"] == field)


class ClassifyTest(unittest.TestCase):
    def test_exact_match_is_correct(self):
        self.assertEqual(ev.classify("a", ["a"])[0], ev.CORRECT)

    def test_no_answer_is_missed(self):
        self.assertEqual(ev.classify("a", [])[0], ev.MISSED)
        self.assertEqual(ev.classify("a", [None])[0], ev.MISSED)

    def test_a_different_answer_is_wrong(self):
        self.assertEqual(ev.classify("a", ["b"])[0], ev.WRONG)

    def test_an_extra_wrong_answer_beside_the_right_one_is_still_wrong(self):
        # the headline bug: right value present + a spurious one used to score "correct"
        st, d = ev.classify("a", ["a", "b"])
        self.assertEqual(st, ev.WRONG)
        self.assertEqual(d["spurious"], ["b"])

    def test_duplicates_of_the_right_answer_are_fine(self):
        self.assertEqual(ev.classify("a", ["a", "A", " a "])[0], ev.CORRECT)

    def test_every_value_in_a_multi_value_key_is_scored(self):
        self.assertEqual(ev.classify(["x", "y"], ["x", "y"])[0], ev.CORRECT)
        st, d = ev.classify(["x", "y"], ["x"])  # one of two found, nothing spurious
        self.assertEqual(st, ev.MISSED)
        self.assertEqual(d["missing"], ["y"])
        self.assertEqual(ev.classify(["x", "y"], ["x", "y", "z"])[0], ev.WRONG)

    def test_no_expected_value_is_not_scored(self):
        self.assertEqual(ev.classify(None, ["a"])[0], ev.NA)


class NormalisationTest(unittest.TestCase):
    def test_mac_separator_style_is_not_a_difference(self):
        for form in ("00:1e:64:ec:f3:08", "00-1E-64-EC-F3-08", "001e64ecf308", "001e.64ec.f308"):
            self.assertEqual(ev.classify("00:1e:64:ec:f3:08", [form], ev.norm_mac)[0], ev.CORRECT, form)

    def test_a_different_mac_is_wrong(self):
        self.assertEqual(ev.classify("00:1e:64:ec:f3:08", ["00:15:fa:50:6f:18"], ev.norm_mac)[0], ev.WRONG)

    def test_hostname_compares_the_machine_label_not_the_dns_suffix(self):
        self.assertEqual(ev.classify("DESKTOP-SKBR25F", ["desktop-skbr25f.local"], ev.norm_host)[0], ev.CORRECT)


class ScoreCaseTest(unittest.TestCase):
    def test_a_fully_correct_run_scores_everything_but_the_unsurfaced_real_name(self):
        r = ev.score_case(KEY, good_answers(), board())
        for f in ("victim.ip", "victim.mac", "victim.hostname", "user.account", "malware.family", "c2.ip"):
            self.assertEqual(status(r, f), ev.CORRECT, f)
        self.assertEqual(status(r, "user.real_name"), ev.MISSED)  # not surfaced yet: a known gap

    def test_a_spurious_extra_victim_is_confidently_wrong(self):
        answers = good_answers() + [ans("victim", host="172.16.1.10")]
        self.assertEqual(status(ev.score_case(KEY, answers, board()), "victim.ip"), ev.WRONG)

    def test_a_spurious_extra_c2_is_confidently_wrong(self):
        answers = good_answers() + [ans("c2", address="203.0.113.7")]
        self.assertEqual(status(ev.score_case(KEY, answers, board()), "c2.ip"), ev.WRONG)

    def test_the_account_is_scored_against_the_victims_sign_in_only(self):
        # ccollier signed in on ANOTHER host must not make the victim's attribution look correct
        answers = [a for a in good_answers() if a["question"] != "signed-in-user"]
        answers.append(ans("signed-in-user", host="172.16.1.99", user="ccollier"))
        self.assertEqual(status(ev.score_case(KEY, answers, board()), "user.account"), ev.MISSED)

    def test_a_wrong_account_on_the_victim_host_is_wrong(self):
        answers = [a for a in good_answers() if a["question"] != "signed-in-user"]
        answers.append(ans("signed-in-user", host="172.16.1.66", user="someone_else"))
        self.assertEqual(status(ev.score_case(KEY, answers, board()), "user.account"), ev.WRONG)

    def test_every_c2_in_a_multi_c2_key_is_scored(self):
        key = dict(KEY, c2=[{"ip": "141.98.10.79"}, {"ip": "203.0.113.7"}])
        one_found = ev.score_case(key, good_answers(), board())
        self.assertEqual(status(one_found, "c2.ip"), ev.MISSED)
        self.assertEqual(detail(one_found, "c2.ip")["missing"], ["203.0.113.7"])
        both = good_answers() + [ans("c2", address="203.0.113.7")]
        self.assertEqual(status(ev.score_case(key, both, board()), "c2.ip"), ev.CORRECT)

    def test_mac_format_differences_do_not_produce_a_false_wrong(self):
        self.assertEqual(status(ev.score_case(KEY, good_answers(), board(mac="00-1E-64-EC-F3-08")),
                                "victim.mac"), ev.CORRECT)


class FindFileTest(unittest.TestCase):
    """find_file must walk every page, and must not treat an unfinished file as ready."""

    def setUp(self):
        self._orig = ev.http_get_json

    def tearDown(self):
        ev.http_get_json = self._orig

    def _pages(self, pages):
        def fake(url, timeout=60):
            n = int(url.split("page=")[1].split("&")[0])
            return {"data": pages[n - 1], "totalPages": len(pages)}
        ev.http_get_json = fake

    def test_a_file_beyond_the_first_page_is_found(self):
        self._pages([[{"fileName": "other.pcap", "status": "completed"}],
                     [{"fileName": "target.pcap", "status": "completed", "fileId": "abc"}]])
        meta, waiting = ev.find_file("http://x", "target.pcap")
        self.assertEqual(meta["fileId"], "abc")
        self.assertIsNone(waiting)

    def test_an_unfinished_file_is_reported_as_in_progress_not_as_missing(self):
        self._pages([[{"fileName": "target.pcap", "status": "processing"}]])
        meta, waiting = ev.find_file("http://x", "target.pcap")
        self.assertIsNone(meta)
        self.assertEqual(waiting, "processing")

    def test_no_such_file_is_none_none(self):
        self._pages([[{"fileName": "other.pcap", "status": "completed"}]])
        self.assertEqual(ev.find_file("http://x", "target.pcap"), (None, None))


class UploadGuardTest(unittest.TestCase):
    def test_a_capture_that_does_not_match_the_manifest_hash_is_refused_before_any_upload(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
            f.write(b"not the capture the key was written for")
            f.flush()
            with self.assertRaises(ev.ApiError) as ctx:
                # a bad hash must be rejected BEFORE curl/network: this URL is unreachable on purpose
                ev.upload_and_wait("http://localhost:9/api/v1", Path(f.name), "0" * 64)
            self.assertIn("does not match the manifest", str(ctx.exception))


class RunSummaryTest(unittest.TestCase):
    def test_an_empty_or_skipped_run_is_incomplete_not_a_pass(self):
        self.assertTrue(ev.is_incomplete([]))
        self.assertTrue(ev.is_incomplete([{"case_id": "x", "status": "pcap_unavailable", "fields": []}]))
        self.assertTrue(ev.is_incomplete([{"case_id": "x", "status": "error", "fields": []}]))

    def test_a_fully_scored_run_is_complete(self):
        self.assertFalse(ev.is_incomplete([{"case_id": "x", "status": "scored", "fields": []}]))

    def test_summary_counts_wrong_and_excludes_unscored_cases(self):
        results = [
            {"case_id": "a", "status": "scored", "fields": [
                {"field": "f1", "status": ev.CORRECT, "detail": None},
                {"field": "f2", "status": ev.WRONG, "detail": None},
                {"field": "f3", "status": ev.MISSED, "detail": None}]},
            {"case_id": "b", "status": "pcap_unavailable", "fields": []},
        ]
        s = ev.summarize(results)
        self.assertEqual((s["cases"], s["cases_scored"]), (2, 1))
        self.assertEqual((s["correct"], s["missed"], s["confidently_wrong"]), (1, 1, 1))

    def test_the_committed_scorecard_carries_no_per_run_file_id(self):
        import json
        import tempfile
        results = [{"case_id": "a", "status": "scored", "analysis": {"suricata": True},
                    "fields": [{"field": "f", "status": ev.CORRECT, "detail": "x"}]}]
        with tempfile.TemporaryDirectory() as d:
            ev.write_scorecard(results, ev.summarize(results), Path(d))
            self.assertNotIn("file_id", (Path(d) / "scorecard.json").read_text())
            self.assertIn("Suricata **on**", (Path(d) / "scorecard.md").read_text())
            json.loads((Path(d) / "scorecard.json").read_text())  # still valid JSON


if __name__ == "__main__":
    unittest.main()
