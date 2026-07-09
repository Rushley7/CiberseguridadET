import sqlite3
from werkzeug.security import generate_password_hash

# Conexion a la base de datos (se creara automaticamente si no existe)
conn = sqlite3.connect('example.db')

# Crear un cursor
c = conn.cursor()

# Crear la tabla de usuarios
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
''')

# CORRECCION VULN #2 (Hash de contrasenas debil):
# Se reemplazo hashlib.sha256() (rapido, sin salt, vulnerable a rainbow
# tables) por generate_password_hash() de Werkzeug, que aplica un
# algoritmo lento (PBKDF2-SHA256 por defecto) con salt aleatorio unico
# por contrasena, haciendo inviables los ataques de diccionario/fuerza
# bruta masivos y los rainbow tables precomputados.
c.execute('''
    INSERT INTO users (username, password, role) VALUES
    ('admin', ?, 'admin'),
    ('user', ?, 'user')
''', (generate_password_hash('password'), generate_password_hash('password')))

# Crear la tabla de comentarios
c.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        comment TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

# Guardar los cambios y cerrar la conexion
conn.commit()
conn.close()

print("Base de datos y tablas creadas con exito.")
