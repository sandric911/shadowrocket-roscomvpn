#!/usr/bin/env python3
"""Сборка Shadowrocket-конфигов и rule-set'ов из списков RoscomVPN.

Источники:
  geosite — https://github.com/hydraponique/roscomvpn-geosite, ветка master, папка data/
            (формат v2fly: domain:, full:, keyword:, regexp:, include:, голые строки)
  geoip   — https://github.com/hydraponique/roscomvpn-geoip, ветка release, папка text/
            (голые CIDR построчно)

Результат:
  rules/*.list             — Surge-style списки для RULE-SET (ТИП,значение на строку)
  roscomvpn.conf           — профиль DEFAULT
  roscomvpn-whitelist.conf — профиль WHITELIST

Примеры:
  python3 build.py --base-url https://raw.githubusercontent.com/USER/REPO/main
  python3 build.py --base-url ... --src-dir ./cache   # из локальной копии, без сети
  python3 build.py --check                             # проверить уже собранные файлы

Только стандартная библиотека, Python 3.9+.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent

GEOSITE_URL = "https://raw.githubusercontent.com/hydraponique/roscomvpn-geosite/master/data/{name}"
GEOIP_URL = "https://raw.githubusercontent.com/hydraponique/roscomvpn-geoip/release/text/{name}.txt"

# Категории geosite, которые используют профили DEFAULT и WHITELIST у RoscomVPN.
# category-geoblock-ru и google-deepmind — серверная маршрутизация, здесь не нужны.
GEOSITE_LISTS = [
    "private", "category-ads", "win-spy", "torrent",
    "google-play", "twitch-ads", "youtube", "telegram", "github",
    "epicgames", "origin", "riot", "escapefromtarkov", "steam", "faceit",
    "twitch", "microsoft", "apple", "pinterest",
    "category-ru", "whitelist",
]
GEOIP_LISTS = ["private", "direct", "whitelist"]

TEMPLATES = {
    "roscomvpn.conf": "templates/roscomvpn.conf.tmpl",
    "roscomvpn-whitelist.conf": "templates/roscomvpn-whitelist.conf.tmpl",
}

GENERATED_PREFIX = "# GENERATED:"
BUILD_PREFIX = "# BUILD:"
USER_AGENT = "shadowrocket-roscomvpn-build/1.0 (+https://github.com)"

LIST_LINE_RE = re.compile(r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR),([^,\s]+)$")
DOMAIN_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")
KEYWORD_RE = re.compile(r"^[a-z0-9._-]+$")
PLACEHOLDER_RE = re.compile(r"\{[A-Z_]+\}")

POLICIES = {"DIRECT", "PROXY", "REJECT", "REJECT-DROP", "REJECT-NO-DROP"}
CONF_RULESET_RE = re.compile(r"^RULE-SET,(\S+),([A-Z-]+)(,no-resolve)?$")
CONF_SIMPLE_RE = re.compile(
    r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN-WILDCARD|IP-CIDR|IP-ASN|GEOIP|DST-PORT|USER-AGENT|URL-REGEX)"
    r",[^,\s]+,([A-Z-]+)(,no-resolve)?$"
)
CONF_LOGIC_RE = re.compile(r"^(AND|OR|NOT),\(.+\),([A-Z-]+)$")
CONF_FINAL_RE = re.compile(r"^FINAL,([A-Z-]+)$")


class BuildError(Exception):
    """Ошибка сборки: сеть, формат апстрима или невалидный результат."""


# ---------------------------------------------------------------------------
# geosite: v2fly-формат → правила Shadowrocket
# ---------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


def _valid_domain(value: str) -> bool:
    return bool(value) and len(value) <= 253 and DOMAIN_RE.match(value) is not None


def regexp_to_rule(pattern: str) -> Optional[str]:
    """Регулярка → DOMAIN-KEYWORD по буквальному префиксу (best effort).

    Shadowrocket не умеет регулярки по домену, поэтому берём начало паттерна до первого
    метасимвола. Если буквального префикса нет или он короче 6 символов — правило
    выбрасывается (например, ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ для одиночных хостов).
    """
    p = pattern.strip()
    if p.startswith("^"):
        p = p[1:]
    if p.startswith(r"(^|\.)"):
        p = p[len(r"(^|\.)"):]
    out: List[str] = []
    i = 0
    while i < len(p):
        ch = p[i]
        if ch == "\\" and i + 1 < len(p) and p[i + 1] in ".-_":
            out.append(p[i + 1])
            i += 2
            continue
        if ch.isalnum() or ch in "-_":
            out.append(ch)
            i += 1
            continue
        break
    literal = "".join(out).lower()
    if len(literal) >= 6 and any(c.isalpha() for c in literal) and KEYWORD_RE.match(literal):
        return f"DOMAIN-KEYWORD,{literal}"
    return None


def convert_geosite_line(line: str) -> Optional[str]:
    """Одна строка v2fly-формата → правило Shadowrocket без политики, либо None.

    None возвращается для комментариев, пустых строк, include: (обрабатывается выше)
    и невалидных записей.
    """
    text = _strip_comment(line)
    if not text:
        return None
    tokens = text.split()
    entry = tokens[0]
    if any(not t.startswith("@") for t in tokens[1:]):
        return None  # после записи допустимы только атрибуты вида @cn
    if ":" in entry:
        kind, _, value = entry.partition(":")
        kind = kind.lower()
    else:
        kind, value = "domain", entry
    if kind == "include":
        return None
    if kind == "regexp":
        return regexp_to_rule(value)
    value = value.strip().lower()
    if kind == "domain":
        return f"DOMAIN-SUFFIX,{value}" if _valid_domain(value) else None
    if kind == "full":
        return f"DOMAIN,{value}" if _valid_domain(value) else None
    if kind == "keyword":
        return f"DOMAIN-KEYWORD,{value}" if value and KEYWORD_RE.match(value) else None
    return None


def convert_geosite(
    text: str,
    name: str,
    fetch_include: Callable[[str], Optional[str]],
    _seen: Optional[Set[str]] = None,
) -> Tuple[List[str], int]:
    """Весь список → (правила без дублей, число выброшенных строк).

    include:другой_список подтягивается через fetch_include (циклы безопасны).
    """
    seen_lists = _seen if _seen is not None else set()
    seen_lists.add(name)
    rules: List[str] = []
    known: Set[str] = set()
    dropped = 0
    for raw in text.splitlines():
        stripped = _strip_comment(raw)
        if not stripped:
            continue
        if stripped.lower().startswith("include:"):
            target = stripped.split(":", 1)[1].split()[0].strip()
            if target in seen_lists:
                continue
            included = fetch_include(target) or ""
            sub_rules, sub_dropped = convert_geosite(included, target, fetch_include, seen_lists)
            dropped += sub_dropped
            for rule in sub_rules:
                if rule not in known:
                    known.add(rule)
                    rules.append(rule)
            continue
        rule = convert_geosite_line(raw)
        if rule is None:
            dropped += 1
            continue
        if rule not in known:
            known.add(rule)
            rules.append(rule)
    return rules, dropped


# ---------------------------------------------------------------------------
# geoip: голые CIDR → IP-CIDR
# ---------------------------------------------------------------------------

def convert_geoip_line(line: str) -> Optional[str]:
    text = _strip_comment(line)
    if not text:
        return None
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return f"IP-CIDR,{net.with_prefixlen}"


def convert_geoip(text: str) -> Tuple[List[str], int]:
    rules: List[str] = []
    known: Set[str] = set()
    dropped = 0
    for raw in text.splitlines():
        if not _strip_comment(raw):
            continue
        rule = convert_geoip_line(raw)
        if rule is None:
            dropped += 1
            continue
        if rule not in known:
            known.add(rule)
            rules.append(rule)
    return rules, dropped


# ---------------------------------------------------------------------------
# Запись файлов и валидация
# ---------------------------------------------------------------------------

def _without_stamp(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines()
        if not line.startswith((GENERATED_PREFIX, BUILD_PREFIX))
    )


def write_list(path: Path, source_url: str, rules: List[str], now: str) -> bool:
    """Записать список; вернуть True, если содержимое изменилось (метка времени не в счёт)."""
    header = [
        f"# NAME: {path.name}",
        f"# SOURCE: {source_url}",
        "# UPSTREAM: RoscomVPN — https://github.com/hydraponique/roscomvpn-routing",
        f"{GENERATED_PREFIX} {now}",
        f"# TOTAL: {len(rules)}",
    ]
    new_text = "\n".join(header + rules) + "\n"
    if path.exists() and _without_stamp(path.read_text(encoding="utf-8")) == _without_stamp(new_text):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_text, encoding="utf-8")
    return True


def validate_list_text(text: str, name: str) -> int:
    """Проверить готовый .list: известные типы, без пробелов у запятых, без дублей."""
    seen: Set[str] = set()
    count = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        if LIST_LINE_RE.match(line) is None:
            raise BuildError(f"{name}:{number}: невалидная строка правила: {line!r}")
        if line in seen:
            raise BuildError(f"{name}:{number}: дубль правила {line}")
        seen.add(line)
        count += 1
    return count


def render_config(template: str, base_url: str, build_date: str) -> str:
    text = template.replace("{BASE_URL}", base_url.rstrip("/")).replace("{BUILD_DATE}", build_date)
    leftover = PLACEHOLDER_RE.search(text)
    if leftover:
        raise BuildError(f"в шаблоне остался неизвестный плейсхолдер {leftover.group(0)}")
    return text


def _rule_section(text: str) -> List[Tuple[int, str]]:
    lines: List[Tuple[int, str]] = []
    inside = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            inside = line == "[Rule]"
            continue
        if inside and line and not line.startswith("#"):
            lines.append((number, line))
    return lines


def validate_config(text: str, base_url: str, available_lists: Set[str]) -> None:
    """Проверить [Rule]: RULE-SET ссылаются на собранные списки, типы известны, FINAL последний."""
    base = base_url.rstrip("/")
    rules = _rule_section(text)
    if not rules:
        raise BuildError("в конфиге нет секции [Rule] или она пуста")
    for number, line in rules[:-1]:
        if CONF_FINAL_RE.match(line):
            raise BuildError(f"строка {number}: FINAL должен быть последним правилом")
    last_number, last = rules[-1]
    match = CONF_FINAL_RE.match(last)
    if match is None:
        raise BuildError(f"строка {last_number}: последним правилом должен быть FINAL, а не {last!r}")
    if match.group(1) not in POLICIES:
        raise BuildError(f"строка {last_number}: неизвестная политика {match.group(1)}")
    for number, line in rules[:-1]:
        ruleset = CONF_RULESET_RE.match(line)
        if ruleset:
            url, policy = ruleset.group(1), ruleset.group(2)
            prefix = f"{base}/rules/"
            if not url.startswith(prefix):
                raise BuildError(f"строка {number}: RULE-SET вне {prefix}: {url}")
            file_name = url[len(prefix):]
            if file_name not in available_lists:
                raise BuildError(f"строка {number}: RULE-SET ссылается на несобранный список {file_name}")
        else:
            simple = CONF_SIMPLE_RE.match(line) or CONF_LOGIC_RE.match(line)
            if simple is None:
                raise BuildError(f"строка {number}: неизвестное правило {line!r}")
            policy = simple.group(2)
        if policy not in POLICIES:
            raise BuildError(f"строка {number}: неизвестная политика {policy}")


def write_config(path: Path, text: str, force: bool) -> bool:
    """Записать конфиг; без force перезаписывать только при изменении тела (метка BUILD не в счёт)."""
    if path.exists() and not force and _without_stamp(path.read_text(encoding="utf-8")) == _without_stamp(text):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True


# ---------------------------------------------------------------------------
# Загрузка источников
# ---------------------------------------------------------------------------

def http_get(url: str, retries: int = 3, timeout: int = 30) -> str:
    last_error: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as error:
            last_error = error
            if attempt < retries:
                time.sleep(2 * attempt)
    raise BuildError(f"не удалось скачать {url}: {last_error}")


def make_fetcher(src_dir: Optional[Path]) -> Callable[[str, str], str]:
    """Вернуть функцию fetch(kind, name): kind ∈ {geosite, geoip}."""
    if src_dir is not None:
        root = Path(src_dir)

        def local(kind: str, name: str) -> str:
            path = root / "geosite" / name if kind == "geosite" else root / "geoip" / f"{name}.txt"
            if not path.exists():
                raise BuildError(f"нет локального файла {path}")
            return path.read_text(encoding="utf-8")

        return local

    def remote(kind: str, name: str) -> str:
        url = (GEOSITE_URL if kind == "geosite" else GEOIP_URL).format(name=name)
        return http_get(url)

    return remote


# ---------------------------------------------------------------------------
# Сборка и проверка
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build(base_url: str, src_dir: Optional[Path] = None, out_dir: Path = ROOT, now: Optional[str] = None) -> Dict:
    now = now or utc_now()
    base_url = base_url.rstrip("/")
    out_dir = Path(out_dir)
    rules_dir = out_dir / "rules"
    fetch = make_fetcher(src_dir)
    report: Dict = {"lists": {}, "changed": False, "base_url": base_url}
    available: Set[str] = set()

    def fetch_include(name: str) -> str:
        return fetch("geosite", name)

    for name in GEOSITE_LISTS:
        rules, dropped = convert_geosite(fetch("geosite", name), name, fetch_include)
        if not rules:
            raise BuildError(f"geosite/{name}: после конвертации пусто — изменился формат апстрима?")
        file_name = f"{name}.list"
        changed = write_list(rules_dir / file_name, GEOSITE_URL.format(name=name), rules, now)
        report["lists"][name] = {"rules": len(rules), "dropped": dropped, "changed": changed}
        report["changed"] = report["changed"] or changed
        available.add(file_name)

    for name in GEOIP_LISTS:
        rules, dropped = convert_geoip(fetch("geoip", name))
        if not rules:
            raise BuildError(f"geoip/{name}: после конвертации пусто — изменился формат апстрима?")
        file_name = f"geoip-{name}.list"
        changed = write_list(rules_dir / file_name, GEOIP_URL.format(name=name), rules, now)
        report["lists"][f"geoip-{name}"] = {"rules": len(rules), "dropped": dropped, "changed": changed}
        report["changed"] = report["changed"] or changed
        available.add(file_name)

    rules_changed = report["changed"]
    for conf_name, template_rel in TEMPLATES.items():
        template = (ROOT / template_rel).read_text(encoding="utf-8")
        text = render_config(template, base_url, now)
        validate_config(text, base_url, available)
        changed = write_config(out_dir / conf_name, text, force=rules_changed)
        report["changed"] = report["changed"] or changed

    for file_name in sorted(available):
        validate_list_text((rules_dir / file_name).read_text(encoding="utf-8"), file_name)
    return report


def _base_url_from_config(text: str, conf_name: str) -> str:
    match = re.search(r"^update-url\s*=\s*(\S+)$", text, re.MULTILINE)
    if match is None or not match.group(1).endswith("/" + conf_name):
        raise BuildError(f"{conf_name}: не найден update-url, оканчивающийся на /{conf_name}")
    return match.group(1)[: -len("/" + conf_name)]


def check(out_dir: Path = ROOT) -> Dict[str, int]:
    """Проверить уже собранные rules/*.list и конфиги без обращения к сети."""
    out_dir = Path(out_dir)
    rules_dir = out_dir / "rules"
    counts: Dict[str, int] = {}
    if not rules_dir.is_dir():
        raise BuildError(f"нет папки {rules_dir}")
    for path in sorted(rules_dir.glob("*.list")):
        counts[path.name] = validate_list_text(path.read_text(encoding="utf-8"), path.name)
    expected = {f"{n}.list" for n in GEOSITE_LISTS} | {f"geoip-{n}.list" for n in GEOIP_LISTS}
    missing = expected - set(counts)
    if missing:
        raise BuildError(f"не хватает списков: {', '.join(sorted(missing))}")
    for conf_name in TEMPLATES:
        path = out_dir / conf_name
        if not path.exists():
            raise BuildError(f"нет файла {path}")
        text = path.read_text(encoding="utf-8")
        validate_config(text, _base_url_from_config(text, conf_name), set(counts))
    return counts


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Сборка Shadowrocket-конфигов из списков RoscomVPN")
    parser.add_argument("--base-url", help="URL, по которому будут доступны файлы репозитория, "
                        "например https://raw.githubusercontent.com/USER/REPO/main")
    parser.add_argument("--src-dir", type=Path, help="локальная копия источников: geosite/<name>, geoip/<name>.txt")
    parser.add_argument("--out-dir", type=Path, default=ROOT, help="куда писать результат (по умолчанию папка скрипта)")
    parser.add_argument("--check", action="store_true", help="только проверить уже собранные файлы")
    args = parser.parse_args(argv)

    try:
        if args.check:
            counts = check(args.out_dir)
            for name, count in counts.items():
                print(f"  {name:<28} {count:>6} правил")
            print(f"OK: {len(counts)} списков и {len(TEMPLATES)} конфига проверены")
            return 0
        if not args.base_url:
            parser.error("нужен --base-url (или --check)")
        report = build(args.base_url, args.src_dir, args.out_dir)
    except BuildError as error:
        print(f"ОШИБКА: {error}", file=sys.stderr)
        return 1

    for name, info in report["lists"].items():
        flag = "изменён" if info["changed"] else "без изменений"
        dropped = f", пропущено {info['dropped']}" if info["dropped"] else ""
        print(f"  {name:<20} {info['rules']:>6} правил{dropped:<16} {flag}")
    print("Конфиги обновлены" if report["changed"] else "Изменений нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())
