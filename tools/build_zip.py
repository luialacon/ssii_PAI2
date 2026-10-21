"""Empaqueta el entregable PAI2-ST2.zip con una lista de inclusión explícita (lista blanca).

Por qué una lista blanca y no "todo menos...": así NUNCA se cuela una clave privada, la base de
datos, el entorno virtual o el enunciado de la asignatura por descuido.

Se incluye: código (src, benchmarks, attacks, tests), el script de capturas, evidencias (pcap,
benchmark, ataques, log de auditoría), documentación (README, GUIA, CHANGELOG, memoria PDF) y
AGENTS.md (registro del uso de IA, evidencia para la reflexión de la memoria).
NO se incluye: certs/ ni data/*.db (se regeneran con `python main.py` opción 1), .git, cachés.

Uso: `python -m tools.build_zip`  ->  escribe PAI2-ST2.zip en la raíz del proyecto.
"""
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOP = "PAI2-ST2"
OUTPUT = ROOT / f"{TOP}.zip"

INCLUDE_DIRS = ["src", "benchmarks", "attacks", "tests", "evidences"]
INCLUDE_FILES = [
    "main.py", "README.md", "GUIA.md", "CHANGELOG.md", "AGENTS.md",
    "requirements.txt", "requirements-dev.txt", "pytest.ini", ".gitignore",
    "tools/__init__.py", "tools/capture_evidence.py", "tools/build_zip.py",
    "docs/Memoria_PAI2_ST2.pdf",
]
EXCLUDED_DIRS = {"__pycache__", ".pytest_cache", ".venv", ".git", ".claude", ".codebase-memory"}
# ".log" fuera: el único que hay es el log de texto de la versión original (formato antiguo);
# la evidencia vigente es audit.jsonl.
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".db", ".sqlite", ".key", ".env", ".keylog", ".log"}
# Excepción deliberada: el keylog de la captura de DEMO se incluye (permite descifrar ESA captura
# en Wireshark). No son claves de producción: son claves de sesión efímeras de una sesión de prueba.
KEEP = {"evidences/pcap/tls13_session.keylog"}


def excluded(rel: Path) -> bool:
    if rel.as_posix() in KEEP:
        return False
    return any(p in EXCLUDED_DIRS for p in rel.parts) or rel.suffix.lower() in EXCLUDED_SUFFIXES


def collect() -> list[Path]:
    files = []
    for d in INCLUDE_DIRS:
        files += [p for p in sorted((ROOT / d).rglob("*")) if p.is_file() and not excluded(p.relative_to(ROOT))]
    missing = [f for f in INCLUDE_FILES if not (ROOT / f).is_file()]
    if missing:
        sys.exit("Faltan ficheros obligatorios para la entrega:\n  - " + "\n  - ".join(missing))
    files += [ROOT / f for f in INCLUDE_FILES]
    return files


def main() -> None:
    files = collect()
    OUTPUT.unlink(missing_ok=True)
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(f, f"{TOP}/{f.relative_to(ROOT).as_posix()}")
    # Comprobación de seguridad: ninguna clave privada dentro del zip.
    with zipfile.ZipFile(OUTPUT) as z:
        # Cabecera PEM contigua de una clave privada. El patrón está partido en dos trozos para que
        # este mismo fichero no lo cumpla (si no, la comprobación se detectaría a sí misma).
        pem_header = re.compile("-----BEGIN (?:[A-Z]+ )?" + "PRIVATE KEY-----")

        def has_pem_private_key(name: str) -> bool:
            return bool(pem_header.search(z.read(name).decode("utf-8", "ignore")))
        bad = [n for n in z.namelist() if n.endswith(".key") or has_pem_private_key(n)]
    if bad:
        OUTPUT.unlink()
        sys.exit(f"ABORTADO: el zip contenía material secreto: {bad}")
    print(f"{OUTPUT.name}: {len(files)} ficheros, {OUTPUT.stat().st_size / 1024:.0f} KB (sin claves privadas)")


if __name__ == "__main__":
    main()
