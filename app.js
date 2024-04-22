const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Conexión a la base de datos SQLite3
const db = new sqlite3.Database('./database.sqlite3', (err) => {
  if (err) {
    console.error('Error al abrir la base de datos', err.message);
  } else {
    console.log('Conexión exitosa a la base de datos SQLite3');
  }
});

// Crear tabla de usuarios si no existe
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)");
});

// Ruta para registro de usuario
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
      if (err) {
        console.error('Error al insertar usuario', err.message);
        res.status(500).send({ error: 'Error al registrar usuario' });
      } else {
        res.status(201).send({ message: 'Usuario registrado exitosamente' });
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error al registrar usuario' });
  }
});

// Ruta para inicio de sesión
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
      if (err) {
        console.error('Error al buscar usuario', err.message);
        res.status(500).send({ error: 'Error al buscar usuario' });
      } else {
        if (!row) {
          res.status(401).send({ error: 'Usuario no encontrado' });
        } else {
          const isPasswordMatch = await bcrypt.compare(password, row.password);
          if (!isPasswordMatch) {
            res.status(401).send({ error: 'Contraseña incorrecta' });
          } else {
            const token = jwt.sign({ username: row.username }, 'secret_key');
            res.status(200).send({ token });
          }
        }
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error al iniciar sesión' });
  }
});

// Iniciar servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
