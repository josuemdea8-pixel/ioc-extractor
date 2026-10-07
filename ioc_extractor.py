#!/usr/bin/env python3
"""IOC Extractor.

Extrai Indicadores de Comprometimento (IOCs) de alertas, tickets e e-mails de phishing:
IPs (com classificação público/interno), URLs, domínios, e-mails, hashes (MD5/SHA-1/SHA-256)
e CVEs. Aceita texto "defanged" (hxxp, [.]), gera saída com defang e exporta em
Markdown, JSON ou CSV. Apenas biblioteca padrão; não faz nenhuma requisição de rede.
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys
from collections import Counter
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse

TYPE_ORDER = ("ip", "url", "domain", "email", "md5", "sha1", "sha256", "cve")
TYPE_LABEL = {"ip": "IPs", "url": "URLs", "domain": "Domínios", "email": "E-mails",
              "md5": "Hashes MD5", "sha1": "Hashes SHA-1", "sha256": "Hashes SHA-256", "cve": "CVEs"}

# Extensões de arquivo que parecem TLD (evita tratar "payload.exe" ou "script.py" como domínio).
FILE_EXTS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "lnk", "msi", "scr", "jar",
    "py", "pyc", "sh", "pl", "rb", "php", "asp", "aspx", "jsp", "html", "htm", "css", "json", "xml",
    "txt", "log", "csv", "md", "ini", "cfg", "conf", "yml", "yaml", "pdf", "doc", "docx", "docm",
    "xls", "xlsx", "xlsm", "ppt", "pptx", "zip", "rar", "7z", "gz", "tar", "iso", "img", "bin",
    "tmp", "dat", "db", "png", "jpg", "jpeg", "gif", "svg", "eml", "msg", "pcap",
}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
NOT_PUBLIC = {"interno", "loopback", "link-local", "reservado"}

URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]{}]+", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}")
IP_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w])(?!\.\d)")
DOMAIN_RE = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
HASH_RES = {n: re.compile(rf"(?<![A-Fa-f0-9])[A-Fa-f0-9]{{{size}}}(?![A-Fa-f0-9])")
            for n, size in (("md5", 32), ("sha1", 40), ("sha256", 64))}


# --------------------------------------------------------------------------- #
# Defang / refang
# --------------------------------------------------------------------------- #
def refang(text: str) -> str:
    """Desfaz o defang (hxxp, [.], (dot), [@], [:]) para permitir a extração."""
    text = re.sub(r"hxxp", "http", text, flags=re.I)
    text = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", ".", text, flags=re.I)
    text = re.sub(r"\[\s*@\s*\]|\[at\]|\(at\)", "@", text, flags=re.I)
    return text.replace("[:]", ":").replace("[://]", "://")


def defang(value: str, kind: str) -> str:
    """Torna o indicador inofensivo para compartilhar (não clicável)."""
    if kind == "url":
        return re.sub(r"^http", "hxxp", value, count=1, flags=re.I).replace(".", "[.]")
    if kind in ("domain", "ip"):
        return value.replace(".", "[.]")
    if kind == "email":
        return value.replace("@", "[@]").replace(".", "[.]")
    return value


# --------------------------------------------------------------------------- #
# Extração
# --------------------------------------------------------------------------- #
def classify_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if any(addr in net for net in DOC_NETS):
        return "documentação"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_unspecified or addr.is_multicast or addr.is_reserved:
        return "reservado"
    if addr.is_private:
        return "interno"
    return "público"


def _valid_ip(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


def _is_ignored(host: str, ignored: set) -> bool:
    return any(host == d or host.endswith("." + d) for d in ignored)


def extract(text: str, ignore_domains=(), exclude_internal=False) -> list[dict]:
    """Extrai IOCs de um texto e devolve registros com tipo, valor, defang, contagem e classe."""
    ignored = {d.lower().strip(".") for d in ignore_domains}
    text = refang(text)
    found = {kind: Counter() for kind in TYPE_ORDER}

    for raw in URL_RE.findall(text):
        url = raw.rstrip(".,;:!?")
        host = (urlparse(url).hostname or "").lower()
        if host and not _is_ignored(host, ignored):
            found["url"][url] += 1
            (found["ip"] if _valid_ip(host) else found["domain"])[host] += 1
    text = URL_RE.sub(" ", text)

    for raw in EMAIL_RE.findall(text):
        email = raw.lower().rstrip(".")
        domain = email.rsplit("@", 1)[1]
        if not _is_ignored(domain, ignored):
            found["email"][email] += 1
            found["domain"][domain] += 1
    text = EMAIL_RE.sub(" ", text)

    for candidate in IP_RE.findall(text):
        if _valid_ip(candidate):
            found["ip"][candidate] += 1

    for raw in DOMAIN_RE.findall(text):
        domain = raw.lower()
        if domain.rsplit(".", 1)[1] in FILE_EXTS or _is_ignored(domain, ignored):
            continue
        found["domain"][domain] += 1

    for kind, pattern in HASH_RES.items():
        for raw in pattern.findall(text):
            if re.search(r"[a-fA-F]", raw):  # descarta números longos só com dígitos
                found[kind][raw.lower()] += 1
    for raw in CVE_RE.findall(text):
        found["cve"][raw.upper()] += 1

    records = []
    for kind in TYPE_ORDER:
        for value, count in sorted(found[kind].items()):
            cls = classify_ip(value) if kind == "ip" else ""
            if exclude_internal and cls in NOT_PUBLIC:
                continue
            records.append({"type": kind, "value": value, "defanged": defang(value, kind),
                            "count": count, "class": cls})
    return records


def read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    file = Path(path)
    if file.suffix.lower() == ".eml":
        with file.open("rb") as handle:
            msg = BytesParser(policy=policy.default).parse(handle)
        parts = [f"{k}: {msg.get(k, '')}" for k in ("From", "Reply-To", "Return-Path", "Subject")]
        parts += [str(h) for h in msg.get_all("Received", [])]
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html") and not part.get_filename():
                try:
                    parts.append(part.get_content())
                except Exception:
                    continue
        return "\n".join(parts)
    return file.read_text(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# Saída
# --------------------------------------------------------------------------- #
def to_markdown(records: list[dict], raw: bool = False) -> str:
    total = len(records)
    lines = ["# IOCs extraídos", "", f"Total de indicadores únicos: **{total}**", ""]
    for kind in TYPE_ORDER:
        group = [r for r in records if r["type"] == kind]
        if not group:
            continue
        lines += [f"## {TYPE_LABEL[kind]} ({len(group)})", ""]
        header = "| Valor | Ocorrências | Classe |" if kind == "ip" else "| Valor | Ocorrências |"
        lines += [header, "|---|---|---|" if kind == "ip" else "|---|---|"]
        for r in group:
            shown = r["value"] if raw else r["defanged"]
            row = f"| `{shown}` | {r['count']} |"
            lines.append(row + (f" {r['class']} |" if kind == "ip" else ""))
        lines.append("")
    if total == 0:
        lines.append("Nenhum indicador encontrado.")
    return "\n".join(lines) + "\n"


def to_json(records: list[dict]) -> str:
    return json.dumps(records, ensure_ascii=False, indent=2)


def to_csv(records: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["type", "value", "defanged", "count", "class"])
    writer.writeheader()
    writer.writerows(records)
    return buffer.getvalue()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extrai IOCs (IPs, URLs, domínios, hashes, CVEs) de alertas e e-mails.")
    parser.add_argument("arquivos", nargs="+", help="arquivos .txt/.log/.eml (use - para ler da entrada padrão)")
    parser.add_argument("--format", choices=("md", "json", "csv"), default="md")
    parser.add_argument("--ignore-domain", action="append", default=[], metavar="DOMINIO",
                        help="ignora um domínio e seus subdomínios (pode repetir)")
    parser.add_argument("--exclude-internal", action="store_true", help="remove IPs internos/loopback/link-local")
    parser.add_argument("--raw", action="store_true", help="mostra valores sem defang no relatório Markdown (cuidado)")
    parser.add_argument("-o", "--output", help="salvar em arquivo")
    args = parser.parse_args(argv)

    text = "\n".join(read_input(p) for p in args.arquivos)
    records = extract(text, args.ignore_domain, args.exclude_internal)
    output = {"md": lambda: to_markdown(records, args.raw), "json": lambda: to_json(records),
              "csv": lambda: to_csv(records)}[args.format]()
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Salvo em {args.output} ({len(records)} indicadores)")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
