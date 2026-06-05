# Ollama Agent

1. Démarrer Ollama : `ollama serve`
2. (optionnel) télécharger un modèle : `ollama pull qwen3:8b`
3. Lancer l'agent : `python ollama_agent.py`

Le script corrige les fichiers du projet choisi et sauvegarde les versions originales dans `.backups/`.
