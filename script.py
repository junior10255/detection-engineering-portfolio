#!/usr/bin/env python3
"""
Detection Engineering Portfolio - Xtreme v16.1 (Hotfix)
===========================================================================
Correção: UnboundLocalError em render_openmetrics (nonlocal lines)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

SCRIPT_VERSION = "16.1"
SCRIPT_NAME = Path(__file__).name

# =============================================================================
# Logging
# =============================================================================

def setup_logging(ci_mode: bool = False) -> None:
    """Configura logging para arquivo + stderr (stderr omitido em modo CI)."""
    Path("audit").mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [
        logging.FileHandler("audit/process.log", encoding="utf-8"),
    ]
    if not ci_mode:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(asctime)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


logger = logging.getLogger(__name__)

# =============================================================================
# Configuração
# =============================================================================

DEFAULT_CONFIG: dict = {
    "max_file_size_mb": 5,
    "max_workers": 8,
    "ci_min_coverage": 50,
    "mitre_tactics": [
        "reconnaissance", "resource_development", "initial_access", "execution",
        "persistence", "privilege_escalation", "defense_evasion", "credential_access",
        "discovery", "lateral_movement", "collection", "command_and_control",
        "exfiltration", "impact",
    ],
    "extra_folders": ["research/pocs", "img", "tools", "audit"],
    "id_to_tactic": {
        "t1595": "reconnaissance",   "t1566": "initial_access",
        "t1059": "execution",        "t1047": "execution",
        "t1053": "persistence",      "t1547": "persistence",
        "t1021": "lateral_movement", "t1003": "credential_access",
        "t1027": "defense_evasion",  "t1070": "defense_evasion",
        "t1087": "discovery",        "t1082": "discovery",
        "t1485": "impact",           "t1071": "command_and_control",
    },
    "heuristic_weights": {
        "credential_access": [["lsass", 3], ["mimikatz", 4], ["password", 1]],
        "lateral_movement":  [["psexec", 4], ["smb", 2],     ["rpc", 1]],
        "discovery":         [["whoami", 3], ["net user", 3], ["ipconfig", 2]],
        "impact":            [["ransom", 4], ["encrypt", 3],  ["shadowcopy", 4]],
        "defense_evasion":   [["disable", 1], ["obfuscation", 3], ["tamper", 3]],
    },
    "heuristic_min_score": 3,
    "max_quality_score": 100,
    "quality_bonus": {
        "description": 20, "author": 10, "falsepositives": 15,
        "references":  10, "tags": 25,   "id": 20,
    },
}


def load_config(config_path: Path) -> dict:
    """
    Carrega config.yaml mesclando com defaults.
    Cria o arquivo com defaults se não existir.
    """
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        cfg = {**DEFAULT_CONFIG, **user_cfg}
        logger.info("Config carregada: %s", config_path)
    else:
        cfg = DEFAULT_CONFIG.copy()
        _safe_write(config_path, yaml.dump(cfg, allow_unicode=True, sort_keys=False))
        logger.info("config.yaml não encontrado — defaults salvos em %s", config_path)
    return cfg


# =============================================================================
# Stats (thread-safe)
# =============================================================================

@dataclass
class Stats:
    """Contêiner thread-safe para métricas acumuladas durante o processamento."""

    invalid_count: int = 0
    sigma_cli_failures: int = 0
    severity: dict = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    logsources: dict = field(default_factory=dict)
    authors:    dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, meta: dict) -> None:
        """Registra metadados de uma regra válida de forma atômica."""
        with self._lock:
            self.severity[meta["level"]] += 1
            a  = meta["author"]
            ls = meta["logsource"]
            self.authors[a]       = self.authors.get(a, 0) + 1
            self.logsources[ls]   = self.logsources.get(ls, 0) + 1

    def increment_invalid(self) -> None:
        with self._lock:
            self.invalid_count += 1

    def increment_sigma_failure(self) -> None:
        with self._lock:
            self.sigma_cli_failures += 1

    def merge(self, other: "Stats") -> None:
        """Agrega stats de outro repositório (modo --repos)."""
        with self._lock:
            self.invalid_count      += other.invalid_count
            self.sigma_cli_failures += other.sigma_cli_failures
            for k in self.severity:
                self.severity[k] += other.severity.get(k, 0)
            for k, v in other.authors.items():
                self.authors[k] = self.authors.get(k, 0) + v
            for k, v in other.logsources.items():
                self.logsources[k] = self.logsources.get(k, 0) + v


# =============================================================================
# I/O utilitários
# =============================================================================

def _safe_write(path: Path, content: str) -> None:
    """
    Escrita atômica com fsync.
    Grava em arquivo temporário → fsync → os.replace (atômico no POSIX).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_p = tempfile.mkstemp(dir=path.parent, suffix=".tmp", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(temp_p, path)
    except Exception as exc:
        Path(temp_p).unlink(missing_ok=True)
        logger.error("Erro ao escrever %s: %s", path, exc)
        raise


def _resolve_collision(dest: Path) -> Path:
    """
    Retorna caminho livre: se dest existir, tenta dest_1 … dest_99.

    Raises:
        FileExistsError: após 99 tentativas.
    """
    if not dest.exists():
        return dest
    stem, suffix = dest.stem, dest.suffix
    for i in range(1, 100):
        candidate = dest.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"Muitas colisões em {dest}")


def _safe_dest(base: Path, *parts: str) -> Path:
    """
    Constrói caminho seguro prevenindo path traversal.

    Raises:
        ValueError: se o destino resolvido estiver fora de base.
    """
    dest      = Path(os.path.realpath(base.joinpath(*parts)))
    base_real = Path(os.path.realpath(base))
    if not (str(dest) == str(base_real) or str(dest).startswith(str(base_real) + os.sep)):
        raise ValueError(f"Path traversal detectado: {dest}")
    return dest


# =============================================================================
# Parsing Sigma
# =============================================================================

def _apply_heuristic(data: dict, cfg: dict) -> str:
    """
    Infere a tática MITRE por palavras-chave quando as tags estão ausentes.

    Returns:
        Nome da tática com maior pontuação, ou 'uncategorized'.
    """
    content_str = str(data).lower()
    weights: dict = cfg["heuristic_weights"]
    min_score: int = cfg["heuristic_min_score"]
    scores = {
        tactic: sum(w for kw, w in terms if kw in content_str)
        for tactic, terms in weights.items()
    }
    best = max(scores, key=scores.get)
    return best if scores[best] >= min_score else "uncategorized"


def parse_sigma(path: Path, cfg: dict, stats: Stats) -> Optional[dict]:
    """
    Extrai metadados de uma regra Sigma.

    Returns:
        dict com file, tactic, level, score, score_percent, author,
        logsource, link e sigma_cli_valid; ou None se inválida.
    """
    max_bytes = int(cfg["max_file_size_mb"] * 1024 * 1024)
    if path.stat().st_size > max_bytes:
        logger.warning("Arquivo muito grande, ignorado: %s", path.name)
        stats.increment_invalid()
        return None

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
    except OSError as exc:
        logger.debug("Erro de I/O em %s: %s", path.name, exc)
        stats.increment_invalid()
        return None

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        logger.debug("YAML inválido em %s: %s", path.name, exc)
        stats.increment_invalid()
        return None

    if not data or not isinstance(data, dict):
        stats.increment_invalid()
        return None

    # Nível
    valid_levels = set(stats.severity.keys())
    level = str(data.get("level", "low")).strip().lower()
    if level not in valid_levels:
        level = "low"

    # Autor / logsource
    author  = str(data.get("author", "Desconhecido")).strip()
    ls_raw  = data.get("logsource") or {}
    logsource = (
        f"{ls_raw.get('product','any')}/{ls_raw.get('service','any')}".lower()
    )

    # Score de qualidade
    bonus: dict    = cfg["quality_bonus"]
    max_score: int = cfg["max_quality_score"]
    raw_score = sum(pt for k, pt in bonus.items() if data.get(k))
    score         = min(max_score, raw_score)
    score_percent = round((score / max_score) * 100, 2)

    # Resolução de tática: tags MITRE → heurística
    tactic    = "uncategorized"
    id_map: dict   = cfg["id_to_tactic"]
    mitre_list: list = cfg["mitre_tactics"]
    tags = data.get("tags") or []
    resolved = False
    if isinstance(tags, list):
        for tag in tags:
            tl = str(tag).lower()
            if "attack.t" in tl:
                m = re.search(r"t\d{4}", tl)
                if m and m.group() in id_map:
                    tactic   = id_map[m.group()]
                    resolved = True
                    break
            elif "attack." in tl:
                t_name = tl.split(".")[-1].replace("-", "_")
                if t_name in mitre_list:
                    tactic   = t_name
                    resolved = True
                    break
    if not resolved:
        tactic = _apply_heuristic(data, cfg)

    meta = {
        "file":            path.name,
        "tactic":          tactic,
        "level":           level,
        "score":           score,
        "score_percent":   score_percent,
        "author":          author,
        "logsource":       logsource,
        "link":            f"Sigma/{tactic}/{path.name}",
        "sigma_cli_valid": None,
    }
    stats.record(meta)
    return meta


# =============================================================================
# sigma-cli
# =============================================================================

_SIGMA_CLI_AVAILABLE: Optional[bool] = None
_SIGMA_CLI_LOCK = threading.Lock()


def _check_sigma_cli() -> bool:
    """Verifica uma única vez (thread-safe) se sigma-cli está no PATH."""
    global _SIGMA_CLI_AVAILABLE
    with _SIGMA_CLI_LOCK:
        if _SIGMA_CLI_AVAILABLE is None:
            try:
                subprocess.run(
                    ["sigma", "--version"],
                    capture_output=True, timeout=5, check=False,
                )
                _SIGMA_CLI_AVAILABLE = True
                logger.info("sigma-cli detectado — validação de schema ativa")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                _SIGMA_CLI_AVAILABLE = False
                logger.warning("sigma-cli não encontrado — validação de schema desativada")
    return bool(_SIGMA_CLI_AVAILABLE)


def validate_with_sigma_cli(path: Path) -> tuple[bool, str]:
    """
    Valida uma regra Sigma via `sigma check`.
    Fallback gracioso se sigma-cli não estiver instalado.

    Returns:
        (is_valid, mensagem)
    """
    if not _check_sigma_cli():
        return True, "sigma-cli indisponível"
    try:
        result = subprocess.run(
            ["sigma", "check", str(path)],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode == 0:
            return True, "OK"
        msg = (result.stderr or result.stdout or "erro desconhecido").strip()
        return False, msg
    except subprocess.TimeoutExpired:
        return False, "Timeout na validação sigma-cli"
    except Exception as exc:
        return False, str(exc)


# =============================================================================
# Descoberta e coleta de arquivos
# =============================================================================

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".svg"}
YAML_EXTS  = {".yml", ".yaml"}


def collect_existing_rules(base: Path, cfg: dict, stats: Stats) -> list[dict]:
    """
    Percorre base/Sigma/ e indexa regras já organizadas.
    Usa suffix.lower() para suportar .yml, .yaml, .YML, .YAML, etc.

    Returns:
        Inventário parcial com metadados das regras existentes.
    """
    sigma_dir = base / "Sigma"
    if not sigma_dir.exists():
        return []

    inventory: list[dict] = []
    for tactic_dir in sorted(sigma_dir.iterdir()):
        if not tactic_dir.is_dir():
            continue
        for yf in tactic_dir.iterdir():
            if yf.is_file() and yf.suffix.lower() in YAML_EXTS:
                meta = parse_sigma(yf, cfg, stats)
                if meta:
                    inventory.append(meta)

    logger.info("Regras já organizadas em Sigma/: %d", len(inventory))
    return inventory


def discover_files(
    base: Path,
    ignored_dirs: set[str],
    ignored_files: set[str],
) -> tuple[list[Path], list[Path], list[Path]]:
    """
    Percorre a árvore (excluindo Sigma/ e outros diretórios gerenciados)
    e separa arquivos por tipo.

    Returns:
        (yaml_files, image_files, md_files_at_root)
    """
    yaml_files:  list[Path] = []
    image_files: list[Path] = []
    md_files:    list[Path] = []

    for root, dirs, files in os.walk(base, topdown=True):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        root_path = Path(root)
        for name in files:
            if name in ignored_files:
                continue
            fp  = root_path / name
            ext = fp.suffix.lower()
            if ext in YAML_EXTS:
                yaml_files.append(fp)
            elif ext in IMAGE_EXTS:
                image_files.append(fp)
            elif ext == ".md" and root_path == base:
                md_files.append(fp)

    return yaml_files, image_files, md_files


# =============================================================================
# Organização de arquivos
# =============================================================================

def organize_file(src: Path, meta: dict, base: Path) -> None:
    """Move regra para Sigma/<tactic>/ com proteção contra traversal e colisão."""
    try:
        dest_dir = _safe_dest(base, "Sigma", meta["tactic"])
        dest     = _resolve_collision(dest_dir / src.name)
    except (ValueError, FileExistsError) as exc:
        logger.error("Não foi possível mover %s: %s", src.name, exc)
        return
    if src.resolve() == dest.resolve():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    logger.info("Movido: %s → Sigma/%s/", src.name, meta["tactic"])


def organize_image(src: Path, base: Path) -> None:
    """Move imagens soltas para img/."""
    img_dir = base / "img"
    if src.resolve().is_relative_to(img_dir.resolve()):
        return
    try:
        dest = _resolve_collision(img_dir / src.name)
    except FileExistsError as exc:
        logger.error(exc)
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    logger.info("Imagem movida: %s → img/", src.name)


def organize_markdown(src: Path, base: Path) -> None:
    """Move arquivos .md da raiz para research/pocs/."""
    pocs_dir = base / "research" / "pocs"
    try:
        dest = _resolve_collision(pocs_dir / src.name)
    except FileExistsError as exc:
        logger.error(exc)
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    logger.info("Markdown movido: %s → research/pocs/", src.name)


# =============================================================================
# Métricas
# =============================================================================

def compute_metrics(inventory: list[dict], stats: Stats, cfg: dict) -> dict:
    """Calcula métricas executivas a partir do inventário consolidado."""
    mitre_tactics: list = cfg["mitre_tactics"]
    total    = len(inventory)
    covered  = {i["tactic"] for i in inventory if i["tactic"] != "uncategorized"}
    missing  = [t for t in mitre_tactics if t not in covered]
    n_mitre  = len(mitre_tactics)
    tactics_covered = len(covered)

    coverage    = round((tactics_covered / n_mitre) * 100, 2) if total else 0.0
    density     = round(total / tactics_covered, 2) if tactics_covered else 0.0
    avg_quality = round(
        sum(i["score_percent"] for i in inventory) / total, 2
    ) if total else 0.0
    high_impact  = stats.severity["critical"] + stats.severity["high"]
    impact_ratio = round((high_impact / total) * 100, 2) if total else 0.0

    tactic_counts: dict[str, int] = {}
    for item in inventory:
        t = item["tactic"]
        tactic_counts[t] = tactic_counts.get(t, 0) + 1

    return {
        "global_coverage":       coverage,
        "active_density":        density,
        "high_impact_ratio":     impact_ratio,
        "average_quality":       avg_quality,
        "total_rules":           total,
        "tactics_covered":       tactics_covered,
        "total_tactics":         n_mitre,
        "missing_tactics":       missing,
        "invalid_rules":         stats.invalid_count,
        "sigma_cli_failures":    stats.sigma_cli_failures,
        "severity_distribution": dict(stats.severity),
        "tactic_counts":         tactic_counts,
        "top_authors":  dict(sorted(stats.authors.items(),    key=lambda x: x[1], reverse=True)[:5]),
        "top_logsources": dict(sorted(stats.logsources.items(), key=lambda x: x[1], reverse=True)[:5]),
        "last_update":           datetime.now().isoformat(),
    }


# =============================================================================
# Relatório: README.md
# =============================================================================

SEV_RANK  = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def render_readme(metrics: dict, inventory: list[dict]) -> str:
    """
    Gera README.md com coluna Link restaurada.
    """
    cov     = metrics["global_coverage"]
    density = metrics["active_density"]
    impact  = metrics["high_impact_ratio"]
    quality = metrics["average_quality"]
    total   = metrics["total_rules"]
    covered = metrics["tactics_covered"]
    n_mitre = metrics["total_tactics"]
    invalid = metrics["invalid_rules"]
    missing = metrics["missing_tactics"]

    sorted_inv = sorted(
        inventory,
        key=lambda x: (SEV_RANK.get(x["level"], 0), x["score_percent"]),
        reverse=True,
    )

    table  = "| Nível | Tática | Regra | Qualidade | Link |\n"
    table += "|:---:|:---|:---|:---:|:---:|\n"
    for item in sorted_inv:
        em    = SEV_EMOJI.get(item["level"], "⚪")
        title = item["tactic"].replace("_", " ").title()
        table += (
            f"| {em} | {title} | `{item['file']}` "
            f"| {item['score_percent']}% | [📄 Ver]({item['link']}) |\n"
        )

    gaps = (
        "## 🚨 Coverage Gaps\n"
        + "".join(f"- {t.replace('_',' ').title()}\n" for t in missing)
        if missing else
        "## ✅ Cobertura Completa\n"
        "Todas as 14 táticas do MITRE ATT&CK possuem pelo menos uma detecção.\n"
    )

    return f"""# 🛡️ Detection Engineering Portfolio

![MITRE Coverage](https://img.shields.io/badge/MITRE%20Coverage-{cov}%25-blueviolet)
![Active Density](https://img.shields.io/badge/Active%20Density-{density}-orange)
![High Impact](https://img.shields.io/badge/High%20Impact-{impact}%25-red)
![Avg Quality](https://img.shields.io/badge/Avg%20Quality-{quality}%25-yellow)

## 📊 Executive Insights
- **Total de Regras:** {total}
- **Táticas Cobertas:** {covered} / {n_mitre}
- **Densidade Real:** {density} regras por tática ativa
- **Qualidade Média:** {quality}%
- **Regras Inválidas Ignoradas:** {invalid}
- **Impacto Alto (Critical/High):** {impact}% das regras

> 💡 Veja o [Dashboard Interativo](dashboard.html) para análise visual completa.

{gaps}

## 📋 Detection Inventory (ordenado por risco)
{table}
---
*Gerado via {SCRIPT_NAME} v{SCRIPT_VERSION} em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""


# =============================================================================
# Relatório: OpenMetrics (Prometheus / Grafana)
# =============================================================================

def render_openmetrics(metrics: dict) -> str:
    """
    Gera metrics.prom no formato OpenMetrics.
    Importável diretamente no Grafana como datasource Prometheus.
    """
    ts = int(datetime.now().timestamp() * 1000)
    lines: list[str] = []

    def add(name: str, help_txt: str, value: float | int, labels: str = "") -> None:
        nonlocal lines   # <--- CORREÇÃO AQUI
        lbl = f"{{{labels}}}" if labels else ""
        lines += [
            f"# HELP {name} {help_txt}",
            f"# TYPE {name} gauge",
            f"{name}{lbl} {value} {ts}",
            "",
        ]

    add("sigma_rules_total",       "Total de regras Sigma processadas",          metrics["total_rules"])
    add("sigma_coverage_percent",  "Cobertura percentual das táticas MITRE",     metrics["global_coverage"])
    add("sigma_quality_average",   "Qualidade média das regras (0-100)",         metrics["average_quality"])
    add("sigma_high_impact_ratio", "Percentual de regras Critical/High",         metrics["high_impact_ratio"])
    add("sigma_active_density",    "Regras por tática ativa",                    metrics["active_density"])
    add("sigma_invalid_rules",     "Regras inválidas ou malformadas",            metrics["invalid_rules"])
    add("sigma_cli_failures",      "Regras que falharam na validação sigma-cli", metrics["sigma_cli_failures"])

    lines += [
        "# HELP sigma_rules_by_severity Regras agrupadas por severidade",
        "# TYPE sigma_rules_by_severity gauge",
    ]
    for sev, count in metrics["severity_distribution"].items():
        lines.append(f'sigma_rules_by_severity{{severity="{sev}"}} {count} {ts}')
    lines.append("")

    lines += [
        "# HELP sigma_rules_by_tactic Regras por tática MITRE ATT&CK",
        "# TYPE sigma_rules_by_tactic gauge",
    ]
    for tactic, count in metrics.get("tactic_counts", {}).items():
        lines.append(f'sigma_rules_by_tactic{{tactic="{tactic}"}} {count} {ts}')

    lines += ["", "# EOF", ""]
    return "\n".join(lines)


# =============================================================================
# Relatório: Dashboard HTML interativo
# =============================================================================

def render_dashboard(metrics: dict, inventory: list[dict]) -> str:
    """
    Gera dashboard.html interativo com Chart.js 4 (dark theme SOC).
    """
    m_json = json.dumps(metrics,   ensure_ascii=False, indent=2)
    i_json = json.dumps(inventory, ensure_ascii=False)

    css = (
        "<style>"
        ":root{--bg:#0d1117;--surf:#161b22;--bord:#30363d;--text:#c9d1d9;--muted:#8b949e;"
        "      --acc:#58a6ff;--crit:#f85149;--high:#d29922;--med:#3fb950;--low:#58a6ff;}"
        "*{box-sizing:border-box;margin:0;padding:0;}"
        "body{background:var(--bg);color:var(--text);font-family:'Segoe UI',monospace;padding:24px;}"
        "h1{font-size:1.6rem;margin-bottom:4px;}"
        ".sub{color:var(--muted);font-size:.85rem;margin-bottom:24px;}"
        ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px;}"
        ".card{background:var(--surf);border:1px solid var(--bord);border-radius:8px;padding:16px;}"
        ".card-val{font-size:1.9rem;font-weight:700;color:var(--acc);}"
        ".card-lbl{color:var(--muted);font-size:.7rem;margin-top:4px;text-transform:uppercase;letter-spacing:.06em;}"
        ".g2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;}"
        ".box{background:var(--surf);border:1px solid var(--bord);border-radius:8px;padding:16px;}"
        ".box h2{font-size:.9rem;color:var(--muted);margin-bottom:12px;}"
        "canvas{max-height:260px;}"
        ".sec{font-size:1rem;font-weight:600;margin:24px 0 12px;border-bottom:1px solid var(--bord);padding-bottom:8px;}"
        "input.srch{width:100%;padding:8px 12px;background:var(--surf);border:1px solid var(--bord);"
        "           border-radius:6px;color:var(--text);font-size:.9rem;margin-bottom:12px;outline:none;}"
        "table{width:100%;border-collapse:collapse;font-size:.83rem;}"
        "th{text-align:left;padding:8px 12px;background:var(--surf);border-bottom:2px solid var(--bord);"
        "   color:var(--muted);cursor:pointer;user-select:none;}"
        "th:hover{color:var(--acc);}"
        "td{padding:7px 12px;border-bottom:1px solid var(--bord);}"
        "tr:hover td{background:rgba(88,166,255,.05);}"
        ".b{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.72rem;font-weight:600;}"
        ".bc{background:rgba(248,81,73,.15);color:var(--crit);}"
        ".bh{background:rgba(210,153,34,.15);color:var(--high);}"
        ".bm{background:rgba(63,185,80,.15);color:var(--med);}"
        ".bl{background:rgba(88,166,255,.15);color:var(--low);}"
        "a.lnk{color:var(--acc);text-decoration:none;font-size:.8rem;}"
        "a.lnk:hover{text-decoration:underline;}"
        ".gap-tag{display:inline-block;background:rgba(248,81,73,.1);color:var(--crit);"
        "         border:1px solid var(--crit);border-radius:4px;padding:2px 8px;margin:3px;font-size:.76rem;}"
        "@media(max-width:700px){.g2{grid-template-columns:1fr;}}"
        "</style>"
    )

    js_template = (
        "<script src='https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js'></script>"
        "<script>"
        "const M=%%M%%;const INV=%%I%%;"
        "document.getElementById('v-tot').textContent=M.total_rules;"
        "document.getElementById('v-cov').textContent=M.global_coverage+'%';"
        "document.getElementById('v-qua').textContent=M.average_quality+'%';"
        "document.getElementById('v-imp').textContent=M.high_impact_ratio+'%';"
        "document.getElementById('v-den').textContent=M.active_density;"
        "document.getElementById('v-inv').textContent=M.invalid_rules;"
        "document.getElementById('v-cli').textContent=M.sigma_cli_failures;"
        "document.getElementById('ts').textContent=M.last_update.replace('T',' ').slice(0,19);"
        "const gEl=document.getElementById('gaps');"
        "if(!M.missing_tactics.length){"
        "  gEl.innerHTML='<span style=\"color:#3fb950\">✅ Todas as 14 táticas cobertas!</span>';"
        "}else{"
        "  gEl.innerHTML=M.missing_tactics.map(t=>'<span class=\"gap-tag\">'+t.replace(/_/g,' ')+'</span>').join('');"
        "}"
        "Chart.defaults.color='#8b949e';"
        "new Chart(document.getElementById('c-sev').getContext('2d'),{"
        "  type:'doughnut',"
        "  data:{labels:['Critical','High','Medium','Low'],"
        "        datasets:[{data:[M.severity_distribution.critical,M.severity_distribution.high,"
        "                        M.severity_distribution.medium,M.severity_distribution.low],"
        "                   backgroundColor:['#f85149','#d29922','#3fb950','#58a6ff'],borderWidth:0}]},"
        "  options:{plugins:{legend:{labels:{color:'#c9d1d9'}}},cutout:'65%'}"
        "});"
        "const tacs=Object.keys(M.tactic_counts||{}).sort();"
        "new Chart(document.getElementById('c-tac').getContext('2d'),{"
        "  type:'bar',"
        "  data:{labels:tacs.map(t=>t.replace(/_/g,' ')),"
        "        datasets:[{label:'Regras',data:tacs.map(t=>M.tactic_counts[t]),"
        "                   backgroundColor:'#58a6ff',borderRadius:4}]},"
        "  options:{indexAxis:'y',plugins:{legend:{display:false}},"
        "           scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#30363d'}},"
        "                   y:{ticks:{color:'#c9d1d9',font:{size:11}},grid:{color:'#30363d'}}}}"
        "});"
        "const lsL=Object.keys(M.top_logsources||{});"
        "new Chart(document.getElementById('c-ls').getContext('2d'),{"
        "  type:'bar',"
        "  data:{labels:lsL,datasets:[{label:'Regras',data:lsL.map(k=>M.top_logsources[k]),"
        "                              backgroundColor:'#3fb950',borderRadius:4}]},"
        "  options:{indexAxis:'y',plugins:{legend:{display:false}},"
        "           scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#30363d'}},"
        "                   y:{ticks:{color:'#c9d1d9',font:{size:11}},grid:{color:'#30363d'}}}}"
        "});"
        "const RANK={critical:4,high:3,medium:2,low:1};"
        "const CLS={critical:'bc',high:'bh',medium:'bm',low:'bl'};"
        "let sortCol='level',sortDir=-1,filtered=[...INV];"
        "function render(){"
        "  filtered.sort((a,b)=>{"
        "    const av=sortCol==='level'?(RANK[a.level]||0):(a[sortCol]??0);"
        "    const bv=sortCol==='level'?(RANK[b.level]||0):(b[sortCol]??0);"
        "    return typeof av==='string'?sortDir*av.localeCompare(bv):sortDir*(av-bv);"
        "  });"
        "  document.getElementById('tbody').innerHTML=filtered.map(r=>{"
        "    const repo=r.repo?` <span style='color:var(--muted);font-size:.7rem'>[${r.repo}]</span>`:'';"
        "    const cli=r.sigma_cli_valid===false?` <span style='color:var(--crit)' title='sigma-cli falhou'>⚠</span>`:'';"
        "    return '<tr>'"
        "      +'<td><span class=\"b '+(CLS[r.level]||'bl')+'\">'+r.level+'</span></td>'"
        "      +'<td>'+r.tactic.replace(/_/g,' ')+'</td>'"
        "      +'<td><code style=\"font-size:.78rem\">'+r.file+'</code>'+repo+cli+'</td>'"
        "      +'<td>'+r.author+'</td>'"
        "      +'<td>'+r.logsource+'</td>'"
        "      +'<td>'+r.score_percent+'%</td>'"
        "      +'<td><a class=\"lnk\" href=\"'+r.link+'\" target=\"_blank\">📄 Ver</a></td>'"
        "      +'</tr>';"
        "  }).join('');"
        "}"
        "document.querySelectorAll('th[data-col]').forEach(th=>{"
        "  th.addEventListener('click',()=>{"
        "    if(sortCol===th.dataset.col)sortDir*=-1;"
        "    else{sortCol=th.dataset.col;sortDir=-1;}"
        "    render();"
        "  });"
        "});"
        "document.getElementById('srch').addEventListener('input',function(){"
        "  const q=this.value.toLowerCase();"
        "  filtered=INV.filter(i=>[i.file,i.tactic,i.level,i.author,i.logsource]"
        "    .some(v=>v.toLowerCase().includes(q)));"
        "  render();"
        "});"
        "render();"
        "</script>"
    )

    js = js_template.replace("%%M%%", m_json).replace("%%I%%", i_json)

    return (
        "<!DOCTYPE html>\n"
        "<html lang='pt-BR'>\n"
        "<head>\n"
        "<meta charset='UTF-8'>\n"
        "<meta name='viewport' content='width=device-width,initial-scale=1.0'>\n"
        f"<title>🛡️ Detection Portfolio Dashboard</title>\n"
        f"{css}\n"
        "</head>\n"
        "<body>\n"
        f"<h1>🛡️ Detection Engineering Portfolio</h1>\n"
        f"<p class='sub'>Atualizado em <span id='ts'></span> &nbsp;|&nbsp; {SCRIPT_NAME} v{SCRIPT_VERSION}</p>\n"
        "<div class='cards'>\n"
        "  <div class='card'><div class='card-val' id='v-tot'>-</div><div class='card-lbl'>Total de Regras</div></div>\n"
        "  <div class='card'><div class='card-val' id='v-cov'>-</div><div class='card-lbl'>Cobertura MITRE</div></div>\n"
        "  <div class='card'><div class='card-val' id='v-qua'>-</div><div class='card-lbl'>Qualidade Média</div></div>\n"
        "  <div class='card'><div class='card-val' id='v-imp'>-</div><div class='card-lbl'>High Impact</div></div>\n"
        "  <div class='card'><div class='card-val' id='v-den'>-</div><div class='card-lbl'>Densidade Ativa</div></div>\n"
        "  <div class='card'><div class='card-val' id='v-inv'>-</div><div class='card-lbl'>Inválidas</div></div>\n"
        "  <div class='card'><div class='card-val' id='v-cli'>-</div><div class='card-lbl'>Falhas sigma-cli</div></div>\n"
        "</div>\n"
        "<div class='g2'>\n"
        "  <div class='box'><h2>Distribuição por Severidade</h2><canvas id='c-sev'></canvas></div>\n"
        "  <div class='box'><h2>Regras por Tática MITRE ATT&amp;CK</h2><canvas id='c-tac'></canvas></div>\n"
        "</div>\n"
        "<div class='g2'>\n"
        "  <div class='box'><h2>Top Log Sources</h2><canvas id='c-ls'></canvas></div>\n"
        "  <div class='box'><h2>🚨 Coverage Gaps</h2><div id='gaps' style='margin-top:8px;line-height:2.2'></div></div>\n"
        "</div>\n"
        "<div class='sec'>📋 Detection Inventory</div>\n"
        "<input class='srch' id='srch' placeholder='🔍 Filtrar por regra, tática, autor, logsource...'>\n"
        "<table>\n"
        "  <thead><tr>\n"
        "    <th data-col='level'>Nível ↕</th>\n"
        "    <th data-col='tactic'>Tática ↕</th>\n"
        "    <th>Regra</th>\n"
        "    <th data-col='author'>Autor ↕</th>\n"
        "    <th>Logsource</th>\n"
        "    <th data-col='score_percent'>Qualidade ↕</th>\n"
        "    <th>Link</th>\n"
        "  </tr></thead>\n"
        "  <tbody id='tbody'></tbody>\n"
        "</table>\n"
        f"{js}\n"
        "</body>\n"
        "</html>\n"
    )


# =============================================================================
# Pipeline por repositório
# =============================================================================

def process_repo(
    base: Path,
    cfg: dict,
    ci_mode: bool,
    use_sigma_cli: bool,
) -> tuple[list[dict], Stats]:
    """
    Processa um repositório completo.
    """
    stats = Stats()

    for tactic in cfg["mitre_tactics"] + ["uncategorized"]:
        (base / "Sigma" / tactic).mkdir(parents=True, exist_ok=True)
    for folder in cfg["extra_folders"]:
        (base / folder).mkdir(parents=True, exist_ok=True)

    ignored_dirs  = {"Sigma", ".git", "audit", "img", "research", "tools"}
    ignored_files = {
        "README.md", "metrics.json", "metrics.prom", "dashboard.html",
        "config.yaml", SCRIPT_NAME, ".gitignore",
    }

    inventory = collect_existing_rules(base, cfg, stats)
    existing  = {item["file"] for item in inventory}

    yaml_files, image_files, md_files = discover_files(base, ignored_dirs, ignored_files)
    yaml_files = [f for f in yaml_files if f.name not in existing]
    logger.info(
        "Arquivos soltos: %d YAML | %d imagens | %d markdown",
        len(yaml_files), len(image_files), len(md_files),
    )

    inv_lock = threading.Lock()

    def process_one(fp: Path) -> Optional[dict]:
        meta = parse_sigma(fp, cfg, stats)
        if meta and use_sigma_cli:
            valid, msg = validate_with_sigma_cli(fp)
            meta["sigma_cli_valid"] = valid
            if not valid:
                stats.increment_sigma_failure()
                logger.warning("sigma-cli FALHOU — %s: %s", fp.name, msg)
        return meta

    with ThreadPoolExecutor(max_workers=cfg["max_workers"]) as executor:
        futures = {executor.submit(process_one, fp): fp for fp in yaml_files}
        for future in as_completed(futures):
            fp = futures[future]
            try:
                meta = future.result()
            except Exception as exc:
                logger.error("Erro inesperado em %s: %s", fp.name, exc)
                continue
            if meta:
                with inv_lock:
                    inventory.append(meta)
                if not ci_mode:
                    organize_file(fp, meta, base)
            else:
                logger.debug("Regra inválida ignorada: %s", fp.name)

    if not ci_mode:
        for img in image_files:
            organize_image(img, base)
        for md in md_files:
            organize_markdown(md, base)

    return inventory, stats


# =============================================================================
# CLI & Main
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="organize_sigma.py",
        description=f"Detection Engineering Portfolio Organizer v{SCRIPT_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python organize_sigma.py                             # organiza + gera todos os relatórios
  python organize_sigma.py --ci                        # CI/CD: valida sem mover arquivos
  python organize_sigma.py --sigma-cli                 # valida schema com sigma-cli
  python organize_sigma.py --repos ./r1 ./r2           # agrega múltiplos repositórios
  python organize_sigma.py --ci --sigma-cli            # CI completo com validação de schema
  python organize_sigma.py --repos ./r1 ./r2 --output ./reports
        """,
    )
    p.add_argument(
        "--ci", action="store_true",
        help=(
            "Modo CI/CD: valida e gera métricas sem mover arquivos. "
            "Imprime metrics.json no stdout. Encerra com exit(1) se cobertura < ci_min_coverage."
        ),
    )
    p.add_argument(
        "--sigma-cli", dest="sigma_cli", action="store_true",
        help="Valida cada regra com `sigma check` (requer sigma-cli instalado).",
    )
    p.add_argument(
        "--repos", nargs="+", metavar="PATH", default=None,
        help="Caminhos de múltiplos repositórios Sigma para agregação de métricas.",
    )
    p.add_argument(
        "--output", metavar="PATH", default=None,
        help="Diretório de saída para relatórios (padrão: primeiro --repo ou cwd).",
    )
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    setup_logging(ci_mode=args.ci)

    mode = "CI/CD" if args.ci else "Normal"
    logger.info("=== Xtreme Organizer v%s | Modo: %s ===", SCRIPT_VERSION, mode)

    repos      = [Path(r).resolve() for r in args.repos] if args.repos else [Path.cwd()]
    output_dir = Path(args.output).resolve() if args.output else repos[0]
    output_dir.mkdir(parents=True, exist_ok=True)

    cfg = load_config(output_dir / "config.yaml")

    combined_inventory: list[dict] = []
    combined_stats = Stats()

    for repo in repos:
        logger.info("── Repositório: %s", repo)
        inventory, stats = process_repo(repo, cfg, args.ci, args.sigma_cli)
        if len(repos) > 1:
            for item in inventory:
                item.setdefault("repo", repo.name)
        combined_inventory.extend(inventory)
        combined_stats.merge(stats)

    metrics = compute_metrics(combined_inventory, combined_stats, cfg)

    _safe_write(output_dir / "metrics.json",
                json.dumps(metrics, indent=4, ensure_ascii=False))
    _safe_write(output_dir / "metrics.prom", render_openmetrics(metrics))

    if args.ci:
        print(json.dumps(metrics, indent=2, ensure_ascii=False))
        min_cov = float(cfg.get("ci_min_coverage", 50))
        if metrics["global_coverage"] < min_cov:
            logger.error(
                "CI FALHOU: cobertura %.1f%% abaixo do mínimo %.1f%%",
                metrics["global_coverage"], min_cov,
            )
            raise SystemExit(1)
        if args.sigma_cli and metrics["sigma_cli_failures"] > 0:
            logger.warning(
                "CI AVISO: %d regra(s) falharam na validação sigma-cli",
                metrics["sigma_cli_failures"],
            )
    else:
        _safe_write(output_dir / "README.md",      render_readme(metrics, combined_inventory))
        _safe_write(output_dir / "dashboard.html", render_dashboard(metrics, combined_inventory))

    logger.info(
        "Finalizado | Regras: %d | Cobertura: %s%% | Qualidade: %s%% | High Impact: %s%%",
        metrics["total_rules"],    metrics["global_coverage"],
        metrics["average_quality"], metrics["high_impact_ratio"],
    )
    if not args.ci:
        logger.info(
            "Gerados em %s: README.md | dashboard.html | metrics.json | metrics.prom",
            output_dir,
        )


if __name__ == "__main__":
    main()