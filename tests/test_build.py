"""Тесты конвертера RoscomVPN → Shadowrocket. Запуск: python3 -m unittest discover -s tests -v"""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import build  # noqa: E402


class GeositeLineTests(unittest.TestCase):
    def conv(self, line):
        return build.convert_geosite_line(line)

    def test_domain_becomes_suffix_and_lowercase(self):
        self.assertEqual(self.conv("domain:Example.COM"), "DOMAIN-SUFFIX,example.com")

    def test_attributes_are_stripped(self):
        self.assertEqual(self.conv("domain:example.com @cn @ads"), "DOMAIN-SUFFIX,example.com")

    def test_full_becomes_domain(self):
        self.assertEqual(self.conv("full:www.example.com"), "DOMAIN,www.example.com")

    def test_keyword(self):
        self.assertEqual(self.conv("keyword:deepl."), "DOMAIN-KEYWORD,deepl.")

    def test_bare_line_is_suffix(self):
        self.assertEqual(self.conv("home.arpa"), "DOMAIN-SUFFIX,home.arpa")

    def test_comments_and_blank_lines(self):
        for line in ("# comment", "", "   ", "\t"):
            self.assertIsNone(self.conv(line), repr(line))

    def test_inline_comment(self):
        self.assertEqual(self.conv("domain:example.com # note"), "DOMAIN-SUFFIX,example.com")

    def test_regexp_with_literal_prefix_becomes_keyword(self):
        line = r"regexp:^github-production-release-asset-[0-9a-zA-Z]{6}\.s3\.amazonaws\.com$"
        self.assertEqual(self.conv(line), "DOMAIN-KEYWORD,github-production-release-asset-")

    def test_regexp_without_literal_prefix_is_dropped(self):
        self.assertIsNone(self.conv(r"regexp:^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"))

    def test_regexp_suffix_group_prefix(self):
        line = r"regexp:(^|\.)dualstack\.apiproxy-.+\.amazonaws\.com$"
        self.assertEqual(self.conv(line), "DOMAIN-KEYWORD,dualstack.apiproxy-")

    def test_invalid_values_are_dropped(self):
        self.assertIsNone(self.conv("domain:bad domain"))
        self.assertIsNone(self.conv("domain:bad,comma"))
        self.assertIsNone(self.conv("domain:"))
        self.assertIsNone(self.conv("domain:.leading.dot"))

    def test_include_is_not_a_rule(self):
        self.assertIsNone(self.conv("include:other"))

    def test_punycode_and_underscore(self):
        self.assertEqual(
            self.conv("domain:xn--80ajghhoc2aj1c8b.xn--p1ai"),
            "DOMAIN-SUFFIX,xn--80ajghhoc2aj1c8b.xn--p1ai",
        )
        self.assertEqual(self.conv("full:_dmarc.example.com"), "DOMAIN,_dmarc.example.com")


class GeositeListTests(unittest.TestCase):
    def test_include_is_resolved_and_cycles_are_safe(self):
        sources = {
            "a": "domain:a.com\ninclude:b\n",
            "b": "domain:b.com\ninclude:a\n",
        }
        rules, dropped = build.convert_geosite(sources["a"], "a", sources.get)
        self.assertEqual(rules, ["DOMAIN-SUFFIX,a.com", "DOMAIN-SUFFIX,b.com"])
        self.assertEqual(dropped, 0)

    def test_dedup_keeps_first_occurrence(self):
        text = "domain:x.com\ndomain:y.com\ndomain:x.com\n"
        rules, _ = build.convert_geosite(text, "t", lambda name: "")
        self.assertEqual(rules, ["DOMAIN-SUFFIX,x.com", "DOMAIN-SUFFIX,y.com"])

    def test_dropped_lines_are_counted(self):
        text = "domain:ok.com\ndomain:bad domain\nregexp:^[a-z]$\n"
        rules, dropped = build.convert_geosite(text, "t", lambda name: "")
        self.assertEqual(rules, ["DOMAIN-SUFFIX,ok.com"])
        self.assertEqual(dropped, 2)


class GeoipTests(unittest.TestCase):
    def test_ipv4_cidr(self):
        self.assertEqual(build.convert_geoip_line("5.8.43.4/30"), "IP-CIDR,5.8.43.4/30")

    def test_ipv6_cidr(self):
        self.assertEqual(build.convert_geoip_line("2a00:1450::/32"), "IP-CIDR,2a00:1450::/32")

    def test_single_ip_gets_prefix(self):
        self.assertEqual(build.convert_geoip_line("10.0.0.1"), "IP-CIDR,10.0.0.1/32")

    def test_host_bits_are_masked(self):
        self.assertEqual(build.convert_geoip_line("1.2.3.5/24"), "IP-CIDR,1.2.3.0/24")

    def test_garbage_and_comments(self):
        for line in ("garbage", "# c", "", "1.2.3.4/33"):
            self.assertIsNone(build.convert_geoip_line(line), repr(line))

    def test_convert_geoip_dedups_and_counts(self):
        rules, dropped = build.convert_geoip("1.1.1.0/24\n1.1.1.0/24\nnope\n")
        self.assertEqual(rules, ["IP-CIDR,1.1.1.0/24"])
        self.assertEqual(dropped, 1)


class ListFileTests(unittest.TestCase):
    def test_write_only_when_rules_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "x.list"
            first = build.write_list(path, "https://src", ["DOMAIN-SUFFIX,a.com"], "2026-01-01 00:00 UTC")
            second = build.write_list(path, "https://src", ["DOMAIN-SUFFIX,a.com"], "2026-02-02 00:00 UTC")
            self.assertTrue(first)
            self.assertFalse(second)
            self.assertIn("2026-01-01", path.read_text())
            third = build.write_list(path, "https://src", ["DOMAIN-SUFFIX,b.com"], "2026-03-03 00:00 UTC")
            self.assertTrue(third)
            self.assertIn("2026-03-03", path.read_text())

    def test_validate_list_rejects_bad_lines(self):
        with self.assertRaises(build.BuildError):
            build.validate_list_text("# NAME: x\nDOMAIN-SUFFIX, a.com\n", "x")
        with self.assertRaises(build.BuildError):
            build.validate_list_text("FOO,bar\n", "x")
        with self.assertRaises(build.BuildError):
            build.validate_list_text("DOMAIN,a.com\nDOMAIN,a.com\n", "x")
        build.validate_list_text("# ok\nDOMAIN-SUFFIX,a.com\nIP-CIDR,1.0.0.0/8\n", "x")


class ConfigTests(unittest.TestCase):
    BASE = "https://example.test/base"

    def test_render_replaces_placeholders(self):
        text = build.render_config("u={BASE_URL}/rules/a.list\nd={BUILD_DATE}\n", self.BASE, "D")
        self.assertEqual(text, "u=https://example.test/base/rules/a.list\nd=D\n")

    def test_render_rejects_unknown_placeholder(self):
        with self.assertRaises(build.BuildError):
            build.render_config("{NOPE}", self.BASE, "D")

    def test_validate_config_accepts_good(self):
        conf = (
            "[General]\nipv6 = false\n[Rule]\n"
            f"RULE-SET,{self.BASE}/rules/a.list,DIRECT,no-resolve\n"
            "AND,((PROTOCOL,UDP),(DST-PORT,443)),REJECT-NO-DROP\n"
            "# GEOIP,RU,DIRECT\n"
            "GEOIP,BY,DIRECT\n"
            "FINAL,PROXY\n[Host]\nx.ru = 1.2.3.4\n"
        )
        build.validate_config(conf, self.BASE, {"a.list"})

    def test_validate_config_missing_list(self):
        conf = f"[Rule]\nRULE-SET,{self.BASE}/rules/missing.list,DIRECT\nFINAL,PROXY\n"
        with self.assertRaises(build.BuildError):
            build.validate_config(conf, self.BASE, {"a.list"})

    def test_validate_config_foreign_base_url(self):
        conf = "[Rule]\nRULE-SET,https://other.test/rules/a.list,DIRECT\nFINAL,PROXY\n"
        with self.assertRaises(build.BuildError):
            build.validate_config(conf, self.BASE, {"a.list"})

    def test_validate_config_final_must_be_last(self):
        conf = f"[Rule]\nFINAL,PROXY\nRULE-SET,{self.BASE}/rules/a.list,DIRECT\n"
        with self.assertRaises(build.BuildError):
            build.validate_config(conf, self.BASE, {"a.list"})

    def test_validate_config_unknown_rule_or_policy(self):
        with self.assertRaises(build.BuildError):
            build.validate_config("[Rule]\nWHATEVER,x,DIRECT\nFINAL,PROXY\n", self.BASE, set())
        with self.assertRaises(build.BuildError):
            build.validate_config("[Rule]\nGEOIP,RU,SOMEWHERE\nFINAL,PROXY\n", self.BASE, set())


class EndToEndTests(unittest.TestCase):
    BASE = "https://raw.githubusercontent.com/user/repo/main"

    def make_sources(self, tmp):
        src = tmp / "src"
        (src / "geosite").mkdir(parents=True)
        (src / "geoip").mkdir(parents=True)
        for name in build.GEOSITE_LISTS:
            (src / "geosite" / name).write_text(f"# {name}\ndomain:{name}.example\n")
        for name in build.GEOIP_LISTS:
            (src / "geoip" / f"{name}.txt").write_text("10.1.0.0/16\n")
        return src

    def test_build_from_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            src = self.make_sources(tmp)
            out = tmp / "out"
            report = build.build(base_url=self.BASE, src_dir=src, out_dir=out, now="2026-01-01 00:00 UTC")
            for name in build.GEOSITE_LISTS:
                self.assertTrue((out / "rules" / f"{name}.list").exists(), name)
            for name in build.GEOIP_LISTS:
                self.assertTrue((out / "rules" / f"geoip-{name}.list").exists(), name)
            for conf_name in build.TEMPLATES:
                text = (out / conf_name).read_text()
                self.assertIn(self.BASE, text)
                self.assertNotIn("{BASE_URL}", text)
                self.assertNotIn("{BUILD_DATE}", text)
                self.assertIn("2026-01-01", text)
            self.assertEqual(report["lists"]["youtube"]["rules"], 1)
            self.assertTrue(report["changed"])
            report2 = build.build(base_url=self.BASE, src_dir=src, out_dir=out, now="2026-02-02 00:00 UTC")
            self.assertFalse(report2["changed"])
            self.assertIn("2026-01-01", (out / "roscomvpn.conf").read_text())

    def test_rule_change_restamps_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            src = self.make_sources(tmp)
            out = tmp / "out"
            build.build(base_url=self.BASE, src_dir=src, out_dir=out, now="2026-01-01 00:00 UTC")
            (src / "geosite" / "youtube").write_text("domain:youtube.example\ndomain:new.example\n")
            report = build.build(base_url=self.BASE, src_dir=src, out_dir=out, now="2026-02-02 00:00 UTC")
            self.assertTrue(report["changed"])
            self.assertIn("2026-02-02", (out / "roscomvpn.conf").read_text())

    def test_empty_source_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            src = self.make_sources(tmp)
            (src / "geosite" / "youtube").write_text("# only comments\n")
            with self.assertRaises(build.BuildError):
                build.build(base_url=self.BASE, src_dir=src, out_dir=tmp / "out", now="2026-01-01 00:00 UTC")

    def test_check_mode_validates_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            src = self.make_sources(tmp)
            out = tmp / "out"
            build.build(base_url=self.BASE, src_dir=src, out_dir=out, now="2026-01-01 00:00 UTC")
            build.check(out)
            (out / "rules" / "youtube.list").write_text("BROKEN LINE\n")
            with self.assertRaises(build.BuildError):
                build.check(out)


if __name__ == "__main__":
    unittest.main()
