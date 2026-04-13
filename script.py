#!/usr/bin/env python3
"""
Detection Engineering Portfolio - Xtreme v18.0 (Enterprise Hardened)
====================================================================
- Correção de bug crítico de movimentação de duplicatas
- Thread-safety total em todas as estruturas compartilhadas
- Hash cache em disco (evita recalcular)
- Controle de concorrência para sigma-cli
- Compatibilidade Python 3.8+
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, Tuple, Dict

SCRIPT_VERSION = "18.0"
SCRIPT_NAME = Path(__file__).name

# =============================================================================
# Logging
# =============================================================================

def setup_logging(ci_mode: bool = False) -> None:
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
    "ci_min_quality": 70,
    "sigma_semaphore": 2,
    "mitre_tactics": [
        "reconnaissance", "resource_development", "initial_access", "execution",
        "persistence", "privilege_escalation", "defense_evasion", "credential_access",
        "discovery", "lateral_movement", "collection", "command_and_control",
        "exfiltration", "impact",
    ],
    "extra_folders": ["research/pocs", "img", "tools", "audit", "duplicates"],
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
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        cfg = {**DEFAULT_CONFIG, **user_cfg}
        logger.info("Config carregada: %s", config_path)
    else:
        cfg = DEFAULT_CONFIG.copy()
        _safe_write(config_path, yaml.dump(cfg, allow_unicode=True, sort_keys=False))
        logger.info("config.yaml criado com defaults em %s", config_path)
    return cfg

# =============================================================================
# Stats (thread-safe)
# =============================================================================

@dataclass
class Stats:
    invalid_count: int = 0
    sigma_cli_failures: int = 0
    duplicate_count: int = 0
    severity: dict = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    logsources: dict = field(default_factory=dict)
    authors:    dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, meta: dict) -> None:
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

    def increment_duplicate(self) -> None:
        with self._lock:
            self.duplicate_count += 1

    def merge(self, other: "Stats") -> None:
        with self._lock:
            self.invalid_count      += other.invalid_count
            self.sigma_cli_failures += other.sigma_cli_failures
            self.duplicate_count    += other.duplicate_count
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
    if not dest.exists():
        return dest
    stem, suffix = dest.stem, dest.suffix
    for i in range(1, 100):
        candidate = dest.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"Muitas colisões em {dest}")

def _safe_dest(base: Path, *parts: str) -> Path:
    dest      = Path(os.path.realpath(base.joinpath(*parts)))
    base_real = Path(os.path.realpath(base))
    if not (str(dest) == str(base_real) or str(dest).startswith(str(base_real) + os.sep)):
        raise ValueError(f"Path traversal detectado: {dest}")
    return dest

def is_relative_to(path: Path, parent: Path) -> bool:
    """Compatível com Python <3.9"""
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False

# =============================================================================
# Hash Cache (persistente em disco)
# =============================================================================

class HashCache:
    def __init__(self, cache_path: Path):
        self.cache_path = cache_path
        self.cache: Dict[str, str] = {}
        self.lock = threading.Lock()
        self._load()

    def _load(self):
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
                logger.info("Hash cache carregado: %d entradas", len(self.cache))
            except Exception as e:
                logger.warning("Falha ao carregar cache: %s", e)

    def save(self):
        with self.lock:
            try:
                with open(self.cache_path, "w", encoding="utf-8") as f:
                    json.dump(self.cache, f, indent=2)
            except Exception as e:
                logger.error("Falha ao salvar hash cache: %s", e)

    def get(self, path: Path) -> Optional[str]:
        key = str(path.resolve())
        with self.lock:
            return self.cache.get(key)

    def set(self, path: Path, file_hash: str):
        key = str(path.resolve())
        with self.lock:
            self.cache[key] = file_hash

def compute_content_hash(path: Path, cache: Optional[HashCache] = None) -> str:
    """SHA256 do conteúdo normalizado, com cache opcional."""
    if cache:
        cached = cache.get(path)
        if cached:
            return cached
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    file_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if cache:
        cache.set(path, file_hash)
    return file_hash

# =============================================================================
# Parsing Sigma
# =============================================================================

def _apply_heuristic(data: dict, cfg: dict) -> str:
    # Usa apenas campos relevantes para reduzir falsos positivos
    relevant = ["title", "description", "detection"]
    content_str = " ".join(str(data.get(f, "")) for f in relevant).lower()
    weights: dict = cfg["heuristic_weights"]
    min_score: int = cfg["heuristic_min_score"]
    scores = {
        tactic: sum(w for kw, w in terms if kw in content_str)
        for tactic, terms in weights.items()
    }
    if not scores:
        return "uncategorized"
    best = max(scores, key=scores.get)
    return best if scores[best] >= min_score else "uncategorized"

def parse_sigma(
    path: Path,
    cfg: dict,
    stats: Stats,
    seen_hashes: Set[str],
    hash_lock: threading.Lock,
    hash_cache: HashCache,
) -> Tuple[Optional[dict], str]:
    """
    Retorna (meta, reason).
    reason pode ser: "ok", "duplicate", "invalid", "too_large", "yaml_error", "io_error"
    """
    max_bytes = int(cfg["max_file_size_mb"] * 1024 * 1024)
    if path.stat().st_size > max_bytes:
        logger.warning("Arquivo muito grande, ignorado: %s", path.name)
        stats.increment_invalid()
        return None, "too_large"

    # Hash (com cache)
    file_hash = compute_content_hash(path, hash_cache)

    # Deduplicação (thread-safe)
    with hash_lock:
        if file_hash in seen_hashes:
            logger.debug("Regra duplicada: %s", path.name)
            stats.increment_duplicate()
            return None, "duplicate"
        seen_hashes.add(file_hash)

    # Leitura do arquivo
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
    except OSError as exc:
        logger.debug("Erro de I/O em %s: %s", path.name, exc)
        stats.increment_invalid()
        return None, "io_error"

    # Parsing YAML
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        logger.debug("YAML inválido em %s: %s", path.name, exc)
        stats.increment_invalid()
        return None, "yaml_error"

    if not data or not isinstance(data, dict):
        stats.increment_invalid()
        return None, "invalid"

    # Nível
    valid_levels = set(stats.severity.keys())
    level = str(data.get("level", "low")).strip().lower()
    if level not in valid_levels:
        level = "low"

    # Autor / logsource
    author  = str(data.get("author", "Desconhecido")).strip()
    ls_raw  = data.get("logsource") or {}
    product  = ls_raw.get("product", "any")
    service  = ls_raw.get("service", "any")
    category = ls_raw.get("category", "any")
    logsource = f"{product}/{service}/{category}".lower()

    # Score de qualidade
    bonus: dict    = cfg["quality_bonus"]
    max_score: int = cfg["max_quality_score"]
    raw_score = 0
    for field, pts in bonus.items():
        val = data.get(field)
        if field == "description":
            if isinstance(val, str) and len(val.strip()) >= 20:
                raw_score += pts
        elif field == "falsepositives":
            if val and (isinstance(val, str) and val.strip()) or (isinstance(val, list) and val):
                raw_score += pts
        elif field == "tags":
            if isinstance(val, list) and len(val) > 0:
                raw_score += pts
        elif field in ("author", "references", "id"):
            if val:
                raw_score += pts
    score         = min(max_score, raw_score)
    score_percent = round((score / max_score) * 100, 2)

    # Tática e técnica
    tactic    = "uncategorized"
    technique = None
    id_map: dict   = cfg["id_to_tactic"]
    mitre_list: list = cfg["mitre_tactics"]
    tags = data.get("tags") or []
    resolved = False
    if isinstance(tags, list):
        for tag in tags:
            tl = str(tag).lower()
            if "attack.t" in tl:
                m = re.search(r"t\d{4}(?:\.\d{3})?", tl)
                if m:
                    tid = m.group().split('.')[0]
                    technique = m.group()
                    if tid in id_map:
                        tactic   = id_map[tid]
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

    # Caminho relativo
    rule_folder = path.stem
    rel_link = f"Sigma/{tactic}/{rule_folder}/{path.name}"

    meta = {
        "file":            path.name,
        "tactic":          tactic,
        "technique_id":    technique,
        "level":           level,
        "score":           score,
        "score_percent":   score_percent,
        "author":          author,
        "logsource":       logsource,
        "link":            rel_link,
        "sigma_cli_valid": None,
        "hash":            file_hash,
    }
    stats.record(meta)
    return meta, "ok"

# =============================================================================
# sigma-cli (com semáforo)
# =============================================================================

_SIGMA_CLI_AVAILABLE: Optional[bool] = None
_SIGMA_CLI_LOCK = threading.Lock()
SIGMA_SEMAPHORE: Optional[threading.Semaphore] = None

def _check_sigma_cli() -> bool:
    global _SIGMA_CLI_AVAILABLE
    with _SIGMA_CLI_LOCK:
        if _SIGMA_CLI_AVAILABLE is None:
            try:
                subprocess.run(["sigma", "--version"], capture_output=True, timeout=5, check=False)
                _SIGMA_CLI_AVAILABLE = True
                logger.info("sigma-cli detectado")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                _SIGMA_CLI_AVAILABLE = False
                logger.warning("sigma-cli não encontrado")
    return bool(_SIGMA_CLI_AVAILABLE)

def validate_with_sigma_cli(path: Path, semaphore: threading.Semaphore) -> tuple[bool, str]:
    if not _check_sigma_cli():
        return True, "sigma-cli indisponível"
    with semaphore:
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

def collect_existing_rules(
    base: Path,
    cfg: dict,
    stats: Stats,
    seen_hashes: Set[str],
    hash_lock: threading.Lock,
    hash_cache: HashCache,
) -> list[dict]:
    sigma_dir = base / "Sigma"
    if not sigma_dir.exists():
        return []

    inventory: list[dict] = []
    for tactic_dir in sigma_dir.iterdir():
        if not tactic_dir.is_dir():
            continue
        for rule_folder in tactic_dir.iterdir():
            if not rule_folder.is_dir():
                continue
            for yf in rule_folder.iterdir():
                if yf.is_file() and yf.suffix.lower() in YAML_EXTS:
                    meta, _ = parse_sigma(yf, cfg, stats, seen_hashes, hash_lock, hash_cache)
                    if meta:
                        inventory.append(meta)

    logger.info("Regras já organizadas: %d", len(inventory))
    return inventory

def discover_files(
    base: Path,
    ignored_dirs: set[str],
    ignored_files: set[str],
) -> tuple[list[Path], list[Path], list[Path]]:
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
    rule_name = src.stem
    try:
        rule_dir = _safe_dest(base, "Sigma", meta["tactic"], rule_name)
    except ValueError as exc:
        logger.error("Erro ao criar diretório para %s: %s", src.name, exc)
        return

    rule_dir.mkdir(parents=True, exist_ok=True)
    poc_dir = rule_dir / "poc"
    poc_dir.mkdir(exist_ok=True)
    (poc_dir / ".gitkeep").touch(exist_ok=True)

    dest_yml = rule_dir / src.name
    if src.resolve() == dest_yml.resolve():
        return
    try:
        dest_yml = _resolve_collision(dest_yml)
    except FileExistsError as exc:
        logger.error(exc)
        return
    shutil.move(str(src), str(dest_yml))
    logger.info("Movido: %s → Sigma/%s/%s/", src.name, meta["tactic"], rule_name)

def organize_duplicate(src: Path, base: Path) -> None:
    dup_dir = base / "duplicates"
    dup_dir.mkdir(exist_ok=True)
    try:
        dest = _resolve_collision(dup_dir / src.name)
    except FileExistsError as exc:
        logger.error(exc)
        return
    shutil.move(str(src), str(dest))
    logger.info("Duplicata movida: %s → duplicates/", src.name)

def organize_image(src: Path, base: Path) -> None:
    img_dir = base / "img"
    if is_relative_to(src.resolve(), img_dir.resolve()):
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
    mitre_tactics: list = cfg["mitre_tactics"]
    total    = len(inventory)
    covered  = {i["tactic"] for i in inventory if i["tactic"] != "uncategorized"}
    missing  = [t for t in mitre_tactics if t not in covered]
    n_mitre  = len(mitre_tactics)
    tactics_covered = len(covered)

    coverage    = round((tactics_covered / n_mitre) * 100, 2) if total else 0.0
    density     = round(total / tactics_covered, 2) if tactics_covered else 0.0
    avg_quality = round(sum(i["score_percent"] for i in inventory) / total, 2) if total else 0.0
    high_impact  = stats.severity["critical"] + stats.severity["high"]
    impact_ratio = round((high_impact / total) * 100, 2) if total else 0.0

    tactic_counts: dict[str, int] = {}
    tactic_quality: dict[str, list[float]] = {}
    for item in inventory:
        t = item["tactic"]
        tactic_counts[t] = tactic_counts.get(t, 0) + 1
        tactic_quality.setdefault(t, []).append(item["score_percent"])

    avg_quality_by_tactic = {
        t: round(sum(scores)/len(scores), 2)
        for t, scores in tactic_quality.items()
    }

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
        "duplicate_rules":       stats.duplicate_count,
        "sigma_cli_failures":    stats.sigma_cli_failures,
        "severity_distribution": dict(stats.severity),
        "tactic_counts":         tactic_counts,
        "tactic_quality":        avg_quality_by_tactic,
        "top_authors":  dict(sorted(stats.authors.items(),    key=lambda x: x[1], reverse=True)[:5]),
        "top_logsources": dict(sorted(stats.logsources.items(), key=lambda x: x[1], reverse=True)[:5]),
        "last_update":           datetime.now().isoformat(),
    }

# =============================================================================
# README
# =============================================================================

SEV_RANK  = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}

def render_readme(metrics: dict, inventory: list[dict]) -> str:
    cov     = metrics["global_coverage"]
    density = metrics["active_density"]
    impact  = metrics["high_impact_ratio"]
    quality = metrics["average_quality"]
    total   = metrics["total_rules"]
    covered = metrics["tactics_covered"]
    n_mitre = metrics["total_tactics"]
    invalid = metrics["invalid_rules"]
    dups    = metrics["duplicate_rules"]
    missing = metrics["missing_tactics"]
    qual_tac = metrics["tactic_quality"]

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
        table += f"| {em} | {title} | `{item['file']}` | {item['score_percent']}% | [📄 Ver]({item['link']}) |\n"

    qual_table = "| Tática | Qualidade Média |\n|:---|:---:|\n"
    for t in sorted(qual_tac.keys()):
        qual_table += f"| {t.replace('_',' ').title()} | {qual_tac[t]}% |\n"

    gaps = (
        "## 🚨 Coverage Gaps\n" + "".join(f"- {t.replace('_',' ').title()}\n" for t in missing)
        if missing else "## ✅ Cobertura Completa\n"
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
- **Regras Inválidas:** {invalid}
- **Regras Duplicadas Ignoradas:** {dups}
- **Impacto Alto (Critical/High):** {impact}% das regras

## 📈 Qualidade por Tática
{qual_table}

{gaps}

## 📋 Detection Inventory (ordenado por risco)
{table}
---
*Gerado via {SCRIPT_NAME} v{SCRIPT_VERSION} em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

# =============================================================================
# OpenMetrics
# =============================================================================

def render_openmetrics(metrics: dict) -> str:
    ts = int(datetime.now().timestamp() * 1000)
    lines: list[str] = []

    def add(name: str, help_txt: str, value: float | int, labels: str = "") -> None:
        nonlocal lines
        lbl = f"{{{labels}}}" if labels else ""
        lines += [
            f"# HELP {name} {help_txt}",
            f"# TYPE {name} gauge",
            f"{name}{lbl} {value} {ts}",
            "",
        ]

    add("sigma_rules_total",       "Total de regras Sigma",                     metrics["total_rules"])
    add("sigma_coverage_percent",  "Cobertura MITRE",                           metrics["global_coverage"])
    add("sigma_quality_average",   "Qualidade média",                           metrics["average_quality"])
    add("sigma_high_impact_ratio", "Percentual Critical/High",                  metrics["high_impact_ratio"])
    add("sigma_active_density",    "Densidade ativa",                           metrics["active_density"])
    add("sigma_invalid_rules",     "Regras inválidas",                          metrics["invalid_rules"])
    add("sigma_duplicate_rules",   "Regras duplicadas",                         metrics["duplicate_rules"])
    add("sigma_cli_failures",      "Falhas sigma-cli",                          metrics["sigma_cli_failures"])

    lines += [
        "# HELP sigma_rules_by_severity Regras por severidade",
        "# TYPE sigma_rules_by_severity gauge",
    ]
    for sev, count in metrics["severity_distribution"].items():
        lines.append(f'sigma_rules_by_severity{{severity="{sev}"}} {count} {ts}')
    lines.append("")

    lines += [
        "# HELP sigma_rules_by_tactic Regras por tática",
        "# TYPE sigma_rules_by_tactic gauge",
    ]
    for tactic, count in metrics.get("tactic_counts", {}).items():
        lines.append(f'sigma_rules_by_tactic{{tactic="{tactic}"}} {count} {ts}')

    lines += ["", "# EOF", ""]
    return "\n".join(lines)

# =============================================================================
# Pipeline por repositório
# =============================================================================

def process_repo(
    base: Path,
    cfg: dict,
    ci_mode: bool,
    use_sigma_cli: bool,
) -> tuple[list[dict], Stats]:
    stats = Stats()
    seen_hashes: Set[str] = set()
    hash_lock = threading.Lock()
    dup_lock = threading.Lock()
    hash_cache = HashCache(base / "hash_cache.json")

    # Semáforo para sigma-cli
    semaphore = threading.Semaphore(cfg.get("sigma_semaphore", 2))

    # Cria pastas base
    for tactic in cfg["mitre_tactics"] + ["uncategorized"]:
        (base / "Sigma" / tactic).mkdir(parents=True, exist_ok=True)
    for folder in cfg["extra_folders"]:
        (base / folder).mkdir(parents=True, exist_ok=True)

    ignored_dirs  = {"Sigma", ".git", "audit", "img", "research", "tools", "duplicates"}
    ignored_files = {
        "README.md", "metrics.json", "metrics.prom", "hash_cache.json",
        "config.yaml", SCRIPT_NAME, ".gitignore",
    }

    inventory = collect_existing_rules(base, cfg, stats, seen_hashes, hash_lock, hash_cache)

    yaml_files, image_files, md_files = discover_files(base, ignored_dirs, ignored_files)
    logger.info(
        "Arquivos soltos: %d YAML | %d imagens | %d markdown",
        len(yaml_files), len(image_files), len(md_files),
    )

    inv_lock = threading.Lock()
    duplicates_to_move: list[Path] = []

    def process_one(fp: Path) -> Optional[dict]:
        meta, reason = parse_sigma(fp, cfg, stats, seen_hashes, hash_lock, hash_cache)
        if meta is None:
            if reason == "duplicate":
                with dup_lock:
                    duplicates_to_move.append(fp)
            return None
        if use_sigma_cli:
            valid, msg = validate_with_sigma_cli(fp, semaphore)
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

    if not ci_mode:
        for fp in duplicates_to_move:
            if fp.exists():
                organize_duplicate(fp, base)
        for img in image_files:
            organize_image(img, base)
        for md in md_files:
            organize_markdown(md, base)

    # Salva cache de hash
    hash_cache.save()

    return inventory, stats

# =============================================================================
# CLI & Main
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="organize_sigma.py",
        description=f"Detection Engineering Portfolio Organizer v{SCRIPT_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--ci", action="store_true", help="Modo CI/CD (não move arquivos)")
    p.add_argument("--sigma-cli", dest="sigma_cli", action="store_true", help="Valida com sigma-cli")
    p.add_argument("--repos", nargs="+", metavar="PATH", help="Múltiplos repositórios")
    p.add_argument("--output", metavar="PATH", help="Diretório de saída para relatórios")
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

    _safe_write(output_dir / "metrics.json", json.dumps(metrics, indent=4, ensure_ascii=False))
    _safe_write(output_dir / "metrics.prom", render_openmetrics(metrics))

    if args.ci:
        print(json.dumps(metrics, indent=2, ensure_ascii=False))
        min_cov = float(cfg.get("ci_min_coverage", 50))
        min_qual = float(cfg.get("ci_min_quality", 70))
        exit_code = 0
        if metrics["global_coverage"] < min_cov:
            logger.error("CI FALHOU: cobertura %.1f%% < %.1f%%", metrics["global_coverage"], min_cov)
            exit_code = 1
        if metrics["average_quality"] < min_qual:
            logger.error("CI FALHOU: qualidade média %.1f%% < %.1f%%", metrics["average_quality"], min_qual)
            exit_code = 1
        if args.sigma_cli and metrics["sigma_cli_failures"] > 0:
            logger.warning("CI AVISO: %d regras falharam no sigma-cli", metrics["sigma_cli_failures"])
        raise SystemExit(exit_code)
    else:
        _safe_write(output_dir / "README.md", render_readme(metrics, combined_inventory))

    logger.info("Finalizado | Regras: %d | Cobertura: %s%% | Qualidade: %s%% | High Impact: %s%%",
                metrics["total_rules"], metrics["global_coverage"],
                metrics["average_quality"], metrics["high_impact_ratio"])
    if not args.ci:
        logger.info("Gerados: README.md | metrics.json | metrics.prom | hash_cache.json")

if __name__ == "__main__":
    main()