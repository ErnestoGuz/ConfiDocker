const mysql = require('mysql2/promise'); // versión con promesas

// Crear la conexión
let connection;

async function conectar() {
  if (!connection) {
    connection = await mysql.createConnection({
      host: 'host.docker.internal', // o IP real del servidor
      user: 'root',
      password: '',
      database: 'dashboard',
      port: 3306
    });
    console.log('Conexión a MySQL establecida');
  }
  return connection;
}

// Cerrar la conexión
async function desconectar() {
  if (connection) {
    await connection.end();
    console.log('Conexión cerrada');
    connection = null;
  }
}

module.exports = { conectar, desconectar };
