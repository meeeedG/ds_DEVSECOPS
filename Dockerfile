# Utiliser une image de base allégée et sécurisée
FROM python:3.11-slim

# Créer un utilisateur non-root pour la sécurité
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Créer le répertoire de travail
WORKDIR /app

# Créer le répertoire pour les données avec permissions appropriées
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Copier uniquement le fichier requirements.txt d'abord (pour le cache Docker)
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY api/ .

# Changer vers l'utilisateur non-root
USER appuser

# Exposer le port
EXPOSE 5000

# Utiliser une commande plus sécurisée
CMD ["python", "-u", "app.py"]
