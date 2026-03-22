# Sécurisation d'une Application Python via une Pipeline CI/CD (DevSecOps)

Ce projet a été réalisé dans le cadre du cours de **DevSecOps** à **Mundiapolis**. L'objectif est de sécuriser une application web Flask vulnérable en intégrant des contrôles de sécurité automatisés dans une pipeline CI/CD GitHub Actions.

## 🚀 Objectifs du Projet

- **Identifier et Corriger** les vulnérabilités courantes (OWASP Top 10).
- **Automatiser** les tests de sécurité (SAST, SCA, Container Scanning).
- **Durcir** l'image Docker de l'application.
- **Mettre en place** une pipeline DevSecOps complète.

## 🛡️ Vulnérabilités Identifiées et Corrections

| Vulnérabilité | Description Initiale | Correction Apportée |
| :--- | :--- | :--- |
| **Injection SQL** | Utilisation de concaténation de chaînes dans les requêtes SQLite. | Utilisation de requêtes paramétrées avec `sqlite3`. |
| **Injection de Log** | Logging direct des entrées utilisateur non filtrées. | Sanétisation des logs pour supprimer les caractères de contrôle (`\n`, `\r`). |
| **Path Traversal** | Accès aux fichiers via des chemins non validés. | Utilisation de `os.path.basename` et validation via `pathlib.Path`. |
| **Cryptographie Faible** | Utilisation potentielle de MD5 ou stockage en clair. | Utilisation de `bcrypt` pour les mots de passe et SHA-256 pour le reste. |
| **Secrets en Clair** | Clés API codées en dur dans le code. | Utilisation de variables d'environnement (`os.getenv`). |
| **Utilisateur Root (Docker)** | Le conteneur s'exécutait en tant que root. | Création d'un `appuser` non-root dans le `Dockerfile`. |
| **Validation d'Entrée** | Pas de validation sur les noms d'utilisateur ou fichiers. | Ajout de regex strictes pour valider les formats d'entrée. |

## 🛠️ Outils de Sécurité Intégrés

La pipeline `.github/workflows/devsecops.yml` utilise les outils suivants :

1.  **GitHub CodeQL (SAST)** : Analyse sémantique du code pour trouver des vulnérabilités complexes.
2.  **Bandit (SAST)** : Scanner de vulnérabilités spécifique à Python (recherche d'appels système dangereux, etc.).
3.  **Safety (SCA)** : Vérifie les dépendances dans `requirements.txt` contre une base de données de vulnérabilités connues.
4.  **Trivy (Container Scan)** : Scanne l'image Docker finale pour détecter des vulnérabilités dans l'OS et les paquets système.

## ⚙️ Architecture de la Pipeline CI/CD

La pipeline se déclenche à chaque `push` sur la branche `main` et exécute les étapes suivantes :
1.  **Checkout** du code.
2.  **Analyse SAST** avec CodeQL et Bandit.
3.  **Analyse SCA** avec Safety.
4.  **Build** de l'image Docker.
5.  **Scan de l'image** avec Trivy (bloque la pipeline si des vulnérabilités `CRITICAL` ou `HIGH` sont trouvées).

## 📦 Installation et Utilisation

### Prérequis
- Python 3.11+
- Docker

### Installation Locale
1.  Cloner le dépôt : `git clone https://github.com/meeeedG/ds_DEVSECOPS.git`
2.  Installer les dépendances : `pip install -r requirements.txt`
3.  Lancer l'application : `python api/app.py`

### Utilisation avec Docker
```bash
docker build -t devsecops-api .
docker run -p 5000:5000 devsecops-api
```

---
**Auteur :** Mohamed G. (meeeedG)  
**Établissement :** Mundiapolis  
**Cours :** DevSecOps - 2026
