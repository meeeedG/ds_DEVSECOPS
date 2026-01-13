from flask import Flask, request, jsonify
import sqlite3
import os
import logging
import bcrypt
import hashlib
import re
from pathlib import Path

app = Flask(__name__)

# Configuration du logging sécurisé
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Récupération des secrets depuis les variables d'environnement
API_KEY = os.getenv("API_KEY", "")
if not API_KEY:
    logging.warning("API_KEY not set in environment variables")

# Validation des entrées utilisateur
def validate_username(username):
    """Valide le nom d'utilisateur"""
    if not username or not isinstance(username, str):
        return False
    # Alphanumérique et underscore uniquement, 3-20 caractères
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def validate_filename(filename):
    """Valide et sécurise le nom de fichier"""
    if not filename or not isinstance(filename, str):
        return False
    # Empêche le path traversal
    filename = os.path.basename(filename)
    # Autorise uniquement les caractères alphanumériques, points, tirets et underscores
    return bool(re.match(r'^[a-zA-Z0-9._-]+$', filename))

def sanitize_log_input(data):
    """Nettoie les données avant logging pour éviter log injection"""
    if isinstance(data, dict):
        return {k: str(v).replace('\n', ' ').replace('\r', ' ') for k, v in data.items()}
    return str(data).replace('\n', ' ').replace('\r', ' ')

@app.route("/auth", methods=["POST"])
def auth():
    """Authentification sécurisée avec requêtes paramétrées"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
        username = data.get("username")
        password = data.get("password")
        
        # Validation des entrées
        if not validate_username(username):
            return jsonify({"status": "error", "message": "Invalid username format"}), 400
        
        if not password or not isinstance(password, str) or len(password) < 8:
            return jsonify({"status": "error", "message": "Invalid password"}), 400
        
        # Requête SQL paramétrée pour éviter l'injection SQL
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        # Utilisation de ? pour les paramètres (requête paramétrée)
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            # Vérification du mot de passe avec bcrypt
            stored_hash = result[0]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                return jsonify({"status": "authenticated"})
        
        return jsonify({"status": "denied"}), 401
    
    except Exception as e:
        logging.error(f"Authentication error: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/encrypt", methods=["POST"])
def encrypt():
    """Chiffrement sécurisé avec SHA-256 (pour hashing, pas pour mots de passe)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
        text = data.get("text", "")
        
        # Validation de l'entrée
        if not text or not isinstance(text, str):
            return jsonify({"status": "error", "message": "Invalid input"}), 400
        
        # Utilisation de SHA-256 au lieu de MD5 (plus sécurisé)
        # Note: Pour les mots de passe, utiliser bcrypt (voir route /auth)
        hashed = hashlib.sha256(text.encode()).hexdigest()
        return jsonify({"hash": hashed})
    
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/file", methods=["POST"])
def read_file():
    """Lecture de fichier sécurisée avec validation du path"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
        filename = data.get("filename")
        
        # Validation stricte du nom de fichier
        if not validate_filename(filename):
            return jsonify({"status": "error", "message": "Invalid filename"}), 400
        
        # Protection contre path traversal
        filename = os.path.basename(filename)
        # Définir un répertoire autorisé
        allowed_dir = Path("/app/data")
        allowed_dir.mkdir(exist_ok=True)
        
        file_path = allowed_dir / filename
        
        # Vérifier que le fichier est bien dans le répertoire autorisé
        if not str(file_path.resolve()).startswith(str(allowed_dir.resolve())):
            return jsonify({"status": "error", "message": "Access denied"}), 403
        
        # Vérifier que le fichier existe
        if not file_path.exists():
            return jsonify({"status": "error", "message": "File not found"}), 404
        
        # Lire le fichier
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        return jsonify({"content": content})
    
    except Exception as e:
        logging.error(f"File read error: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/log", methods=["POST"])
def log_data():
    """Logging sécurisé avec protection contre log injection"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
        # Nettoyage des données pour éviter log injection
        sanitized_data = sanitize_log_input(data)
        logging.info(f"User input: {sanitized_data}")
        
        return jsonify({"status": "logged"})
    
    except Exception as e:
        logging.error(f"Logging error: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/health", methods=["GET"])
def health():
    """Endpoint de santé sans divulgation d'informations sensibles"""
    return jsonify({
        "status": "healthy",
        "service": "api"
    })

if __name__ == "__main__":
    # Désactiver le mode debug en production
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
