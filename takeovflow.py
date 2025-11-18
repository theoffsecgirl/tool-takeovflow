#!/usr/bin/env python3
"""
takeovflow – Advanced Subdomain Takeover Scanner

Versión mejorada con:
- Comprobación de herramientas externas
- Modos pasivo / activo
- Salida JSON opcional
- Soporte para templates personalizados de nuclei
- Detección básica de patrones de CNAME típicos de takeover
"""

import argparse
import subprocess
import shutil
import sys
import tempfile
import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


REQUIRED_TOOLS = [
    "subfinder",
    "assetfinder",
    "subjack",
    "dnsx",
    "httpx",
    "nuclei",
    "dig",
    "jq",
    "curl",
]

CNAME_TAKEOVER_PATTERNS = [
    "amazonaws.com",
    "cloudfront.net",
    "herokudns.com",
    "github.io",
    "githubusercontent.com",
    "azurewebsites.net",
    "trafficmanager.net",
    "fastly.net",
    "edgesuite.net",
    "akamai.net",
    "unbouncepages.com",
    "wordpress.com",
    "zendesk.com",
]


def print_banner():
    print("=" * 60)
    print(" takeovflow – Subdomain Takeover Scanner")
    print(" by TheOffSecGirl")
    print("=" * 60)
    print()


def run_cmd(cmd: List[str], verbose: bool = False) -> str:
    if verbose:
        print(f"[cmd] {' '.join(cmd)}")
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode(errors="ignore")
    except subprocess.CalledProcessError:
        return ""
    except FileNotFoundError:
        return ""


def check_tool(tool: str) -> bool:
    return shutil.which(tool) is not None


def ensure_tools(verbose: bool = False):
    missing = [t for t in REQUIRED_TOOLS if not check_tool(t)]
    if missing:
        print("[!] Faltan herramientas necesarias:")
        for m in missing:
            print(f"   - {m}")
        print("\nInstálalas antes de ejecutar este script.")
        sys.exit(1)
    if verbose:
        print("[+] Todas las herramientas externas requeridas están disponibles.\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="takeovflow – Advanced Subdomain Takeover Scanner"
    )
    parser.add_argument("-d", "--domain", help="Dominio único a analizar")
    parser.add_argument("-f", "--file", help="Archivo con dominios (uno por línea)")
    parser.add_argument("-l", "--list", help="Lista de dominios separada por comas")
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Número de hilos para herramientas externas (por defecto 50)",
    )
    parser.add_argument(
        "-r",
        "--rate",
        type=int,
        default=2,
        help="Rate limit aproximado para algunas herramientas (por defecto 2)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Modo verbose",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Solo técnicas pasivas (no escaneos activos)",
    )
    parser.add_argument(
        "--active-only",
        action="store_true",
        help="Solo fase activa (asume subdominios ya descubiertos)",
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Generar también informe en JSON",
    )
    parser.add_argument(
        "--nuclei-templates",
        help="Ruta a templates personalizados de nuclei",
    )
    return parser.parse_args()


def load_domains_from_file(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            d = line.strip()
            if d and not d.startswith("#"):
                domains.append(d)
    return domains


def normalize_domains(args: argparse.Namespace) -> List[str]:
    domains: List[str] = []

    if args.domain:
        domains.append(args.domain.strip())

    if args.file:
        domains.extend(load_domains_from_file(args.file))

    if args.list:
        parts = [p.strip() for p in args.list.split(",")]
        domains.extend([p for p in parts if p])

    # dedupe y limpia
    clean: List[str] = []
    for d in domains:
        d = d.lower()
        if d.startswith("http://"):
            d = d[len("http://") :]
        if d.startswith("https://"):
            d = d[len("https://") :]
        d = d.strip("/")
        if d and d not in clean:
            clean.append(d)

    if not clean:
        print("[!] No se han proporcionado dominios válidos.")
        sys.exit(1)

    return clean


def discover_subdomains(domain: str, tmpdir: Path, threads: int, verbose: bool) -> Path:
    subfinder_out = tmpdir / f"{domain}_subfinder.txt"
    assetfinder_out = tmpdir / f"{domain}_assetfinder.txt"
    combined_out = tmpdir / f"{domain}_subdomains_all.txt"

    # subfinder
    cmd_subfinder = [
        "subfinder",
        "-d",
        domain,
        "-silent",
        "-o",
        str(subfinder_out),
    ]
    run_cmd(cmd_subfinder, verbose=verbose)

    # assetfinder
    cmd_assetfinder = [
        "assetfinder",
        "--subs-only",
        domain,
    ]
    out_asset = run_cmd(cmd_assetfinder, verbose=verbose)
    if out_asset:
        assetfinder_out.write_text(out_asset, encoding="utf-8")

    # combinar y deduplicar
    subs: List[str] = []
    for p in [subfinder_out, assetfinder_out]:
        if p.exists():
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if s and s not in subs:
                        subs.append(s)
    subs.sort()
    combined_out.write_text("\n".join(subs), encoding="utf-8")

    if verbose:
        print(f"[+] {domain}: {len(subs)} subdominios descubiertos (pasivo)")

    return combined_out


def resolve_subdomains(
    domain: str, subs_file: Path, tmpdir: Path, threads: int, verbose: bool
) -> Dict[str, Any]:
    """Usa dnsx + httpx para obtener subdominios vivos y algunos metadatos básicos."""
    results: Dict[str, Any] = {
        "resolved": [],
        "httpx": [],
    }

    if not subs_file.exists():
        return results

    # dnsx
    dnsx_out = tmpdir / f"{domain}_dnsx.txt"
    cmd_dnsx = [
        "dnsx",
        "-silent",
        "-resp",
        "-l",
        str(subs_file),
        "-o",
        str(dnsx_out),
    ]
    run_cmd(cmd_dnsx, verbose=verbose)

    resolved_subs: List[str] = []
    if dnsx_out.exists():
        for line in dnsx_out.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.split()
            if parts:
                resolved_subs.append(parts[0].strip())

    resolved_subs = sorted(set(resolved_subs))
    results["resolved"] = resolved_subs

    # httpx
    httpx_out = tmpdir / f"{domain}_httpx.txt"
    cmd_httpx = [
        "httpx",
        "-silent",
        "-status-code",
        "-title",
        "-follow-redirects",
        "-threads",
        str(threads),
        "-l",
        str(subs_file),
        "-o",
        str(httpx_out),
    ]
    run_cmd(cmd_httpx, verbose=verbose)

    httpx_results: List[Dict[str, Any]] = []
    if httpx_out.exists():
        for line in httpx_out.read_text(encoding="utf-8", errors="ignore").splitlines():
            entry = line.strip()
            if not entry:
                continue
            httpx_results.append({"raw": entry})

    results["httpx"] = httpx_results

    if verbose:
        print(f"[+] {domain}: {len(resolved_subs)} subdominios resueltos (dnsx)")
        print(f"[+] {domain}: {len(httpx_results)} servicios HTTP detectados (httpx)")

    return results


def run_subjack(domain: str, subs_file: Path, tmpdir: Path, verbose: bool) -> Path:
    out_file = tmpdir / f"{domain}_subjack.txt"
    if not subs_file.exists():
        return out_file

    fingerprints = tmpdir / "fingerprints.json"
    if not fingerprints.exists():
        url = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"
        cmd_curl = ["curl", "-sL", url, "-o", str(fingerprints)]
        run_cmd(cmd_curl, verbose=verbose)

    cmd = [
        "subjack",
        "-w",
        str(subs_file),
        "-t",
        "100",
        "-timeout",
        "30",
        "-ssl",
        "-c",
        str(fingerprints),
        "-v",
        "-o",
        str(out_file),
    ]
    run_cmd(cmd, verbose=verbose)

    return out_file


def run_nuclei(
    domain: str,
    subs_file: Path,
    tmpdir: Path,
    threads: int,
    templates: Optional[str],
    verbose: bool,
) -> Path:
    out_file = tmpdir / f"{domain}_nuclei.txt"
    if not subs_file.exists():
        return out_file

    # por defecto usamos tags de takeover
    cmd = [
        "nuclei",
        "-silent",
        "-l",
        str(subs_file),
        "-tags",
        "takeover",
        "-o",
        str(out_file),
        "-c",
        str(threads),
    ]

    # si el usuario pasa templates, sustituimos
    if templates:
        cmd = [
            "nuclei",
            "-silent",
            "-l",
            str(subs_file),
            "-t",
            templates,
            "-o",
            str(out_file),
            "-c",
            str(threads),
        ]

    run_cmd(cmd, verbose=verbose)
    return out_file


def analyze_cname_patterns(
    domain: str, subs_file: Path, tmpdir: Path, verbose: bool
) -> Path:
    """Usa dig para revisar CNAME y buscar patrones típicos de takeover."""
    out_file = tmpdir / f"{domain}_cname_patterns.txt"
    if not subs_file.exists():
        return out_file

    suspicious: List[str] = []

    with subs_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            sub = line.strip()
            if not sub:
                continue
            cmd = ["dig", sub, "CNAME", "+short"]
            cname_out = run_cmd(cmd, verbose=False)
            cname = cname_out.strip()
            if not cname:
                continue
            for pattern in CNAME_TAKEOVER_PATTERNS:
                if pattern in cname:
                    suspicious.append(f"{sub} -> {cname}")
                    break

    if suspicious:
        out_file.write_text("\n".join(suspicious), encoding="utf-8")

    if verbose:
        print(f"[+] {domain}: {len(suspicious)} CNAME sospechosos detectados")

    return out_file


def parse_subjack_results(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not path.exists():
        return findings

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        entry = line.strip()
        findings.append({"source": "subjack", "raw": entry})
    return findings


def parse_nuclei_results(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not path.exists():
        return findings

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        entry = line.strip()
        findings.append({"source": "nuclei", "raw": entry})
    return findings


def parse_cname_results(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not path.exists():
        return findings
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "->" not in line:
            continue
        sub, cname = [p.strip() for p in line.split("->", 1)]
        findings.append(
            {
                "source": "cname-pattern",
                "subdomain": sub,
                "cname": cname,
            }
        )
    return findings


def build_markdown_report(
    report_path: Path, summary: Dict[str, Any], verbose: bool
):
    lines: List[str] = []
    lines.append(f"# Subdomain Takeover Report")
    lines.append("")
    lines.append(f"Generado: {datetime.utcnow().isoformat()} UTC")
    lines.append("")
    lines.append("## Resumen general")
    lines.append("")
    lines.append(f"- Dominios analizados: **{len(summary['domains'])}**")
    total_subs = sum(len(d.get("subdomains", [])) for d in summary["domains"].values())
    lines.append(f"- Subdominios totales descubiertos: **{total_subs}**")
    total_takeovers = sum(
        len(d.get("potential_takeovers", []))
        for d in summary["domains"].values()
    )
    lines.append(f"- Posibles takeovers detectados: **{total_takeovers}**")
    lines.append("")

    for domain, data in summary["domains"].items():
        lines.append(f"---")
        lines.append(f"## Dominio: `{domain}`")
        lines.append("")
        lines.append(
            f"- Subdominios descubiertos: **{len(data.get('subdomains', []))}**"
        )
        lines.append(
            f"- Subdominios resueltos (dnsx): **{len(data.get('resolved', []))}**"
        )
        lines.append(
            f"- Posibles takeovers: **{len(data.get('potential_takeovers', []))}**"
        )
        lines.append("")

        if data.get("potential_takeovers"):
            lines.append("### Posibles takeovers")
            lines.append("")
            for finding in data["potential_takeovers"]:
                src = finding.get("source", "unknown")
                raw = finding.get("raw") or ""
                sub = finding.get("subdomain") or ""
                cname = finding.get("cname") or ""
                if raw:
                    lines.append(f"- **[{src}]** {raw}")
                else:
                    lines.append(
                        f"- **[{src}]** `{sub}` -> `{cname}`"
                    )
            lines.append("")

        if data.get("httpx"):
            lines.append("### Servicios HTTP detectados (httpx)")
            lines.append("")
            for entry in data["httpx"][:50]:
                lines.append(f"- `{entry.get('raw','')}`")
            if len(data["httpx"]) > 50:
                lines.append(f"- ... ({len(data['httpx']) - 50} más)")
            lines.append("")

        if data.get("subdomains"):
            lines.append("### Subdominios descubiertos (primeros 50)")
            lines.append("")
            for s in data["subdomains"][:50]:
                lines.append(f"- `{s}`")
            if len(data["subdomains"]) > 50:
                lines.append(f"- ... ({len(data['subdomains']) - 50} más)")
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    if verbose:
        print(f"[+] Informe Markdown generado en: {report_path}")


def main():
    print_banner()
    args = parse_args()

    ensure_tools(verbose=args.verbose)
    domains = normalize_domains(args)
    if args.verbose:
        print(f"[+] Dominios a analizar: {', '.join(domains)}\n")

    tmpdir_str = tempfile.mkdtemp(prefix="takeovflow_tmp_")
    tmpdir = Path(tmpdir_str)

    summary: Dict[str, Any] = {"domains": {}}

    for domain in domains:
        if args.verbose:
            print(f"[*] Analizando dominio: {domain}")

        domain_data: Dict[str, Any] = {}
        subs_file: Optional[Path] = None

        # Fase pasiva
        if not args.active_only:
            subs_file = discover_subdomains(
                domain, tmpdir=tmpdir, threads=args.threads, verbose=args.verbose
            )
            subdomains_list: List[str] = []
            if subs_file.exists():
                subdomains_list = [
                    s.strip()
                    for s in subs_file.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()
                    if s.strip()
                ]
            domain_data["subdomains"] = subdomains_list
        else:
            if args.verbose:
                print(
                    "[!] Modo --active-only: no se realiza descubrimiento pasivo. "
                    "Debes proporcionar tú los subdominios (no implementado aquí)."
                )

        # Fase activa
        if not args.passive_only and subs_file and subs_file.exists():
            resolved_info = resolve_subdomains(
                domain,
                subs_file=subs_file,
                tmpdir=tmpdir,
                threads=args.threads,
                verbose=args.verbose,
            )
            domain_data["resolved"] = resolved_info.get("resolved", [])
            domain_data["httpx"] = resolved_info.get("httpx", [])

            # subjack
            subjack_out = run_subjack(
                domain, subs_file=subs_file, tmpdir=tmpdir, verbose=args.verbose
            )
            subjack_findings = parse_subjack_results(subjack_out)

            # nuclei
            nuclei_out = run_nuclei(
                domain,
                subs_file=subs_file,
                tmpdir=tmpdir,
                threads=args.threads,
                templates=args.nuclei_templates,
                verbose=args.verbose,
            )
            nuclei_findings = parse_nuclei_results(nuclei_out)

            # CNAME patterns
            cname_out = analyze_cname_patterns(
                domain, subs_file=subs_file, tmpdir=tmpdir, verbose=args.verbose
            )
            cname_findings = parse_cname_results(cname_out)

            domain_data["potential_takeovers"] = (
                subjack_findings + nuclei_findings + cname_findings
            )
        else:
            domain_data.setdefault("resolved", [])
            domain_data.setdefault("httpx", [])
            domain_data.setdefault("potential_takeovers", [])

        summary["domains"][domain] = domain_data
        if args.verbose:
            print()

    # Generar informe
    now = datetime.utcnow().strftime("%Y%m%d")
    report_md = Path.cwd() / f"subdomain_takeover_report_{now}.md"
    build_markdown_report(report_md, summary, verbose=args.verbose)

    if args.json_output:
        report_json = Path.cwd() / f"subdomain_takeover_report_{now}.json"
        report_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        if args.verbose:
            print(f"[+] Informe JSON generado en: {report_json}")

    print("[✓] Análisis completado.")
    print(f"    Informe Markdown: {report_md}")
    if args.json_output:
        print(f"    Informe JSON:     {report_json}")


if __name__ == "__main__":
    main()
