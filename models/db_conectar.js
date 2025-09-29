const mysql = require('mysql2');

// Configurar la conexión
const connection = mysql.createConnection({
    host: 'host.docker.internal',  // O la IP del servidor MySQL
    user: 'root',       // Usuario de MySQL
    password: '',       // Contraseña de MySQL (dejar vacío si no tiene)
    database: 'dashboard', // Nombre de tu base de datos
    port: 3306
});

// Conectar a MySQL
connection.connect((err) => {
    if (err) {
        console.error('Error de conexión:', err);
        return;
    }
    console.log('Conexión a MySQL establecida');
});

// Exportar la conexión
module.exports = connection;