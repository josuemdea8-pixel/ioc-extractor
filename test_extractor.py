import csv
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import ioc_extractor as ioc  # noqa: E402

SAMPLE = ROOT / "samples" / "alerta_phishing.txt"


def values(records, kind):
    return {r["value"] for r in records if r["type"] == kind}


class ExtractorTests(unittest.TestCase):
    def test_refang_and_defang(self):
        self.assertEqual(ioc.refang("hxxps://evil[.]example/x"), "https://evil.example/x")
        self.assertEqual(ioc.defang("http://evil.example/x", "url"), "hxxp://evil[.]example/x")
        self.assertEqual(ioc.defang("a@b.example", "email"), "a[@]b[.]example")

    def test_ip_classification(self):
        records = ioc.extract("8.8.8.8 10.0.0.5 127.0.0.1 169.254.1.1 203.0.113.9")
        classes = {r["value"]: r["class"] for r in records if r["type"] == "ip"}
        self.assertEqual(classes, {"8.8.8.8": "público", "10.0.0.5": "interno", "127.0.0.1": "loopback",
                                   "169.254.1.1": "link-local", "203.0.113.9": "documentação"})

    def test_invalid_ip_and_version_numbers_are_ignored(self):
        records = ioc.extract("IP 999.1.1.1 e versão 1.2.3.4.5 não contam")
        self.assertEqual(values(records, "ip"), set())

    def test_urls_from_defanged_text(self):
        records = ioc.extract("Acesse hxxp://198.51.100.23/a.php e hxxps://golpe[.]example/login.")
        self.assertEqual(values(records, "url"), {"http://198.51.100.23/a.php", "https://golpe.example/login"})
        self.assertIn("198.51.100.23", values(records, "ip"))
        self.assertIn("golpe.example", values(records, "domain"))

    def test_file_names_are_not_domains(self):
        records = ioc.extract("Baixou payload.exe, script.py e Comprovante.pdf.exe de cdn.golpe.example")
        self.assertEqual(values(records, "domain"), {"cdn.golpe.example"})

    def test_hashes_by_type(self):
        md5, sha1, sha256 = "a" * 32, "b" * 40, "c" * 64
        records = ioc.extract(f"{md5} {sha1} {sha256.upper()} {'1' * 32}")
        self.assertEqual(values(records, "md5"), {md5})
        self.assertEqual(values(records, "sha1"), {sha1})
        self.assertEqual(values(records, "sha256"), {sha256})

    def test_cve_normalized_and_counted(self):
        records = ioc.extract("cve-2024-3400 e CVE-2024-3400 de novo, CVE-2023-23397")
        counts = {r["value"]: r["count"] for r in records if r["type"] == "cve"}
        self.assertEqual(counts, {"CVE-2024-3400": 2, "CVE-2023-23397": 1})

    def test_ignore_domain_and_exclude_internal(self):
        text = "https://www.microsoft.com/a evil.example 10.1.1.1 8.8.4.4"
        records = ioc.extract(text, ignore_domains=["microsoft.com"], exclude_internal=True)
        self.assertEqual(values(records, "domain"), {"evil.example"})
        self.assertEqual(values(records, "ip"), {"8.8.4.4"})
        self.assertEqual(values(records, "url"), set())

    def test_sample_and_exports(self):
        records = ioc.extract(SAMPLE.read_text(encoding="utf-8"))
        self.assertIn("login-banco.example", values(records, "domain"))
        self.assertIn("maria.silva@empresa.example", values(records, "email"))
        self.assertEqual(len(values(records, "sha256")), 1)
        parsed = json.loads(ioc.to_json(records))
        self.assertEqual(len(parsed), len(records))
        rows = list(csv.DictReader(io.StringIO(ioc.to_csv(records))))
        self.assertEqual(len(rows), len(records))
        self.assertNotIn("http://", ioc.to_markdown(records))  # relatório sai com defang


if __name__ == "__main__":
    unittest.main()
