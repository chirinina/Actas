from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from docx import Document
# from docx.shared import Pt # Not used in your original, so keeping it out unless needed
# from docx.enum.text import WD_ALIGN_PARAGRAPH # Not used in your original
import io
import json
import os
import random # Your original import
from functools import wraps

# --- Configuration ---
USERS_FILE = 'users.json'
# IMPORTANT: Change this in a real application!
SECRET_KEY = 'your_very_secret_key_for_session_management_v2' # Changed slightly for clarity

app = Flask(__name__)
app.secret_key = SECRET_KEY

# --- YOUR EXISTING DOCUMENT PROCESSING FUNCTIONS (UNCHANGED) ---
def reemplazar_en_runs(parrafos, campos):
    for parrafo in parrafos:
        texto_total = "".join(run.text for run in parrafo.runs)
        # Check if any key is present before attempting replacement
        original_texto_total = texto_total
        for clave, valor in campos.items():
            if clave in texto_total:
                texto_total = texto_total.replace(clave, valor)

        # Only rebuild runs if text actually changed
        if texto_total != original_texto_total: # Check against the text before any replacement this iteration
            # Clear existing runs and add the new combined text
            # This simplified approach might lose some specific run-level formatting
            # if your placeholders split complex formatting.
            # For robust replacement preserving formatting, a more granular approach is needed.
            # However, for simple text placeholders, this is often sufficient.
            for i in range(len(parrafo.runs)):
                parrafo.runs[i].text = ""
            if parrafo.runs: # Ensure there's at least one run to put text into
                parrafo.runs[0].text = texto_total
            else: # If no runs (empty paragraph), add a new run
                parrafo.add_run(texto_total)


def reemplazar_en_documento(doc, campos):
    reemplazar_en_runs(doc.paragraphs, campos)
    for tabla in doc.tables:
        for fila in tabla.rows:
            for celda in fila.cells:
                reemplazar_en_runs(celda.paragraphs, campos)

# --- NEW Helper Functions for User Management ---
def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w', encoding='utf-8') as f: # Create if not exists
            json.dump([], f)
        return []
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        # If file is corrupted, backup and create a new one or handle error
        print(f"Warning: {USERS_FILE} is corrupted. Please check it.")
        return [] # Return empty list if JSON is malformed

def save_users(users_data):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users_data, f, indent=2, ensure_ascii=False)

# --- NEW Decorators for Route Protection ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            # For API-like requests, return JSON error. For page loads, redirect.
            if request.endpoint and (request.endpoint.startswith('admin_') or request.is_json):
                 return jsonify(success=False, message="Autenticación requerida."), 401
            return redirect(url_for('index', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required # Admin must also be logged in
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            if request.endpoint and (request.endpoint.startswith('admin_') or request.is_json):
                return jsonify(success=False, message="Acceso de administrador requerido."), 403
            return redirect(url_for('index')) # Or a specific "unauthorized" page
        return f(*args, **kwargs)
    return decorated_function


# --- MODIFIED Index Route ---
@app.route('/')
def index():
    # This route now serves the main page which includes the login form
    # or the app if already logged in.
    # The random values are now handled by JavaScript after login.
    if 'username' in session:
        return render_template('index.html', logged_in_user=session.get('username'), user_role=session.get('role'))
    return render_template('index.html') # This is the new HTML with login UI

# --- NEW Login/Logout Routes ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    users = load_users()
    user = next((u for u in users if u['username'] == username), None)

    # IMPORTANT: In a real app, HASH passwords and compare hashes!
    if user and user['password'] == password: # Simplistic password check
        if user.get('is_active', False):
            session['username'] = user['username']
            session['role'] = user.get('role', 'user')
            return jsonify({'success': True, 'role': session['role'], 'username': session['username']})
        else:
            return jsonify({'success': False, 'message': 'Cuenta desactivada.'})
    return jsonify({'success': False, 'message': 'Usuario o contraseña incorrectos.'})

@app.route('/logout')
@login_required # User must be logged in to log out
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('index'))

# --- NEW Admin Routes ---
@app.route('/admin/users', methods=['GET'])
@admin_required
def get_admin_users():
    users = load_users()
    users_safe = [{'username': u['username'], 'role': u.get('role', 'user'), 'is_active': u.get('is_active', True)} for u in users]
    return jsonify({'success': True, 'users': users_safe})

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def add_admin_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password') # HASH THIS in real app
    role = data.get('role', 'user')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Usuario y contraseña son requeridos.'})

    users = load_users()
    if any(u['username'] == username for u in users):
        return jsonify({'success': False, 'message': 'El nombre de usuario ya existe.'})

    users.append({'username': username, 'password': password, 'role': role, 'is_active': True})
    save_users(users)
    return jsonify({'success': True, 'message': 'Usuario añadido correctamente.'})

@app.route('/admin/users/update', methods=['POST'])
@admin_required
def update_admin_user():
    data = request.get_json()
    username_to_update = data.get('username')
    is_active = data.get('is_active')
    new_password = data.get('new_password')
    new_role = data.get('new_role')

    users = load_users()
    user_found = False
    for user_obj in users: # Renamed to avoid conflict with 'user' module if imported
        if user_obj['username'] == username_to_update:
            if is_active is not None:
                user_obj['is_active'] = is_active
            if new_password:
                user_obj['password'] = new_password # HASH IT!
            if new_role:
                 user_obj['role'] = new_role
            user_found = True
            break
    
    if not user_found:
        return jsonify({'success': False, 'message': 'Usuario no encontrado.'})

    save_users(users)
    return jsonify({'success': True, 'message': 'Usuario actualizado.'})

@app.route('/admin/users/delete', methods=['POST'])
@admin_required
def delete_admin_user():
    data = request.get_json()
    username_to_delete = data.get('username')

    if username_to_delete == session.get('username'):
         return jsonify({'success': False, 'message': 'No puedes eliminar tu propia cuenta de administrador activa.'})

    users = load_users()
    original_len = len(users)
    users = [user_obj for user_obj in users if user_obj['username'] != username_to_delete]

    if len(users) == original_len:
        return jsonify({'success': False, 'message': 'Usuario no encontrado.'})
    
    save_users(users)
    return jsonify({'success': True, 'message': 'Usuario eliminado.'})


# --- MODIFIED Acta Generation Route ---
@app.route('/generar', methods=['POST'])
@login_required # Protect this route
def generar():
    # Your existing logic for preparing fields for the template
    campos = {}
    for clave, valor in request.form.items():
        # Ensure all expected numeric fields are present, default to '0' if missing or empty
        if clave.endswith("_N") and not valor.strip():
            campos[f"{{{{{clave}}}}}"] = "0" 
        elif clave.endswith("_LI") and not valor.strip():
             campos[f"{{{{{clave}}}}}"] = "(vacío)" # Placeholder for empty literal fields
        else:
            campos[f"{{{{{clave}}}}}"] = valor


    # Ensure all ITEM and TOTAL fields are in `campos` even if not submitted in form,
    # to prevent KeyError if template expects them.
    for i in range(1, 10):
        if f"{{{{ITEM{i}_N}}}}" not in campos:
            campos[f"{{{{ITEM{i}_N}}}}"] = "0" # Default if missing
        if f"{{{{ITEM{i}_LI}}}}" not in campos:
            campos[f"{{{{ITEM{i}_LI}}}}"] = "(no provisto)" # Default if missing
    
    if f"{{{{TOTAL_N}}}}" not in campos:
        campos[f"{{{{TOTAL_N}}}}"] = "0.00"
    if f"{{{{TOTAL_LI}}}}" not in campos:
        campos[f"{{{{TOTAL_LI}}}}"] = "(no calculado)"

    # Load your Word template
    try:
        doc = Document("plantilla_acta.docx")
    except Exception as e:
        print(f"Error loading plantilla_acta.docx: {e}")
        return "Error: No se pudo cargar la plantilla del documento.", 500

    reemplazar_en_documento(doc, campos)

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)

    # Use a safe filename, remove potentially problematic characters
    postulante_name = request.form.get('POSTULANTE', 'documento_acta')
    safe_postulante_name = "".join(c if c.isalnum() or c in (' ', '_', '-') else '_' for c in postulante_name).rstrip()
    filename = f"Acta_{safe_postulante_name.replace(' ', '_')}.docx"
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

if __name__ == '__main__':
    # Ensure users.json exists, create if not
    if not os.path.exists(USERS_FILE):
        print(f"'{USERS_FILE}' no encontrado. Creando uno vacío...")
        initial_admin = [{
            "username": "admin",
            "password": "changeme", # Remind user to change this
            "role": "admin",
            "is_active": True
        }]
        save_users(initial_admin)
        print(f"'{USERS_FILE}' creado con un usuario admin por defecto (admin/changeme). ¡Cambie la contraseña!")
    
    app.run(debug=True)