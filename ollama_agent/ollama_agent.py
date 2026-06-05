#!/usr/bin/env python3
"""Ollama Code Agent - simple local repair assistant for Windows."""

import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import List

import requests

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b")


def print_banner() -> None:
    print("=" * 60)
    print("   OLLAMA CODE AGENT")
    print("=" * 60)
    print("Base URL :", OLLAMA_BASE_URL)
    print("Modèle   :", DEFAULT_MODEL)
    print("")


def check_ollama() -> None:
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=20)
        response.raise_for_status()
        data = response.json()
        models = [item.get("name") for item in data.get("models", []) if item.get("name")]
        if not models:
            print("[WARN] Aucun modèle Ollama n'est disponible. Lancez 'ollama pull qwen3:8b'.")
            return
        print("Modèles disponibles :")
        for model in models:
            marker = "<-- défaut" if model == DEFAULT_MODEL else ""
            print(f"  - {model} {marker}")
    except Exception as exc:
        print("[ERREUR] Impossible de joindre Ollama.")
        print("Vérifiez que le serveur tourne avec : ollama serve")
        print("Erreur détaillée :", exc)
        sys.exit(1)


def choose_project_dir() -> Path:
    env_dir = os.environ.get("PROJECT_DIR", "").strip()
    if env_dir:
        candidate = Path(env_dir).expanduser().resolve()
        if candidate.exists():
            return candidate
        print(f"[WARN] Le chemin fourni via PROJECT_DIR n'existe pas : {candidate}")

    raw = input("Chemin du projet à corriger (Entrée = dossier courant) : ").strip()
    candidate = Path(raw).expanduser() if raw else Path(".").resolve()
    if not candidate.exists() or not candidate.is_dir():
        print("[ERREUR] Le chemin n'est pas un dossier valide.")
        sys.exit(1)
    return candidate


def collect_files(project_dir: Path) -> List[Path]:
    excluded = {".git", ".backups", "node_modules", "logs", "dist", "build", ".venv", "venv", "ollama_agent", ".vscode"}
    files = []
    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in excluded for part in path.parts):
            continue
        if path.parts.count("invitations-web-main") > 1:
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf"}:
            continue
        files.append(path)
    return sorted(files)


def choose_targets(files: List[Path], project_dir: Path) -> List[Path]:
    print("\nFichiers détectés :")
    for index, file_path in enumerate(files, start=1):
        print(f"  {index:>2}. {file_path.relative_to(project_dir)}")

    choice = input("Choisir un fichier ('all' pour tous) : ").strip().lower()
    if choice in ("", "all"):
        return files

    try:
        index = int(choice) - 1
        if 0 <= index < len(files):
            return [files[index]]
    except ValueError:
        pass

    candidate = Path(choice)
    for file_path in files:
        if file_path.relative_to(project_dir) == candidate:
            return [file_path]
    print("[WARN] Choix non reconnu, correction sur tous les fichiers.")
    return files


def extract_code_block(text: str) -> str:
    match = re.search(r"```(?:python|javascript|json|html|css|txt)?\n(.*?)```", text, re.S | re.I)
    if match:
        return match.group(1).strip()
    return text.strip()


def ask_for_instruction() -> str:
    instruction = input("Instruction pour l'IA (ex. 'corrige les erreurs et garde le code propre') : ").strip()
    return instruction or "Améliore ce fichier et corrige les erreurs évidentes sans changer sa logique globale."


def generate_fixed_content(file_path: Path, original: str, instruction: str) -> str:
    prompt = f"""
Tu es un assistant de correction de code local.
Objectif : corriger le fichier ci-dessous sans ajouter d'explications.
Règles :
- Garde la structure et les noms existants si possible.
- Corrige les erreurs évidentes, la syntaxe et les problèmes de logique simple.
- Si le fichier est déjà correct, retourne exactement son contenu original.
- Retourne UNIQUEMENT le contenu final du fichier, sans commentaire, sans intro.

Chemin du fichier : {file_path}

Instruction utilisateur : {instruction}

Fichier actuel :
""" + original

    payload = {
        "model": DEFAULT_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 4096},
    }
    response = requests.post(f"{OLLAMA_BASE_URL}/api/generate", json=payload, timeout=600)
    response.raise_for_status()
    data = response.json()
    answer = data.get("response", "")
    fixed = extract_code_block(answer)
    if not fixed:
        return original
    return fixed


def backup_file(file_path: Path, backups_dir: Path, project_dir: Path) -> Path:
    backup_dir = backups_dir / time.strftime("%Y%m%d-%H%M%S")
    relative_path = file_path.relative_to(project_dir)
    backup_path = backup_dir / relative_path
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file_path, backup_path)
    return backup_path


def main() -> None:
    print_banner()
    check_ollama()

    project_dir = choose_project_dir()
    files = collect_files(project_dir)
    if not files:
        print("Aucun fichier à corriger dans ce dossier.")
        return

    targets = choose_targets(files, project_dir)
    instruction = ask_for_instruction()
    backups_dir = project_dir / ".backups"
    backups_dir.mkdir(exist_ok=True)

    print("\nCorrection en cours...")
    for file_path in targets:
        try:
            original = file_path.read_text(encoding="utf-8")
            if not original.strip():
                print(f"[SKIP] {file_path.relative_to(project_dir)} (vide)")
                continue
            fixed = generate_fixed_content(file_path, original, instruction)
            if fixed == original:
                print(f"[OK] {file_path.relative_to(project_dir)} (aucun changement nécessaire)")
                continue

            backup_path = backup_file(file_path, backups_dir, project_dir)
            file_path.write_text(fixed, encoding="utf-8")
            print(f"[UPDATED] {file_path.relative_to(project_dir)} -> sauvegarde {backup_path.relative_to(project_dir)}")
        except Exception as exc:
            print(f"[ERREUR] {file_path.relative_to(project_dir)} : {exc}")

    print("\nTerminé. Les sauvegardes sont dans :", backups_dir)


if __name__ == "__main__":
    main()
