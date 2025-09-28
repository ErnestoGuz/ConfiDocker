//Configuracion --Montar el servidor
require('dotenv').config();
const nodemailer = require("nodemailer");
const express = require("express");
const mongoose = require('mongoose');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require("bcrypt");
const app = express();
const session = require('express-session');
//Conexion a mysql
const connection = require('./models/db_conectar.js');

//Definir el Puerto de Salida
const port = 5040;

//Configurar EJS como Motor de Plantillas
app.set("view engine", "ejs");

// Middleware para manejar datos del formulario
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

//importar body-parser
//const { error } = require('console');
app.use(bodyParser.json());

//Servir archivos estaticos desde public
app.use(express.static("public"));

//Manejo de sesiones
app.use(session({
    secret: 'clave',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Asegúrate de que sea `true` solo si usas HTTPS
}));


app.use((req, res, next) => {
    res.locals.rol = req.session.rol || ''; //  Hace que `rol` esté disponible en todas las vistas
    next();
});
// Conexion a MongoDB
mongoose.connect('mongodb://host.docker.internal:27017/UsuariosDash'
    ,{
      useNewUrlParser: true,
      useUnifiedTopology: true
 }
).then(()=>{
    console.log("Conectado a MongoDB correctamente");
 }).catch(err =>{
    console.error("Error al conectar con MongoDB:",err);
 });

const userSchema = mongoose.Schema({
    nombre_usuario: String,
    roles: String,
    correo: String,
    password: String
})

const UserMongo = mongoose.model('usuariosses', userSchema);

// Configurar Nodemailer
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER, // Correo remitente
        pass: process.env.EMAIL_PASS  // Contraseña de aplicación
    }
});


/* ////////////////////////////////////////////////// */
//Conexión a la base de datos MongoDB para usuarios
// mongoose.connect('mongodb://localhost:27017/UsuariosBD', {})
//   .then(() => console.log('Conectado a la base de datos UsuariosBD'))
//   .catch(err => console.error('Error al conectar con la base de datos:', err));

// // Definición del esquema para la colección usuarios
// const usuarioSchema = new mongoose.Schema({
//   name: String,
//   email: String,
//   pass: String
// });

// const Usuario = mongoose.model('Usuario', usuarioSchema);

// Redirige la página principal al login
app.get("/", function (req, res) {
    res.redirect("/login");
});

// Página de inicio de sesión
app.get("/login", function (req, res) {
    res.render("login", { titulo: "Iniciar Sesión" });
});

// Nueva ruta para la creación de tickets
app.get("/creacionticket", function (req, res) {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    let consulta;
    let params = [];

    if (req.session.rol.toLowerCase() === 'administrador') {
        // Si es administrador, obtiene todos los tickets
        consulta = `
        SELECT t.id, t.nombre_problemas, t.prioridad, 
               u.nombre AS nombre_empleado, t.estado, 
               DATE_FORMAT(t.fecha_creacion, '%Y/%m/%d') AS fecha_creacion
        FROM tickets t
        JOIN usuarios u ON t.empleado_id = u.id
        ORDER BY t.fecha_creacion DESC
        LIMIT 10
        `;
    } else if (req.session.rol.toLowerCase() === 'empleado') {
        // Si es empleado, obtiene solo sus propios tickets
        consulta = `
        SELECT t.id, t.nombre_problemas, t.prioridad, 
               u.nombre AS nombre_empleado, t.estado, 
               DATE_FORMAT(t.fecha_creacion, '%Y/%m/%d') AS fecha_creacion
        FROM tickets t
        JOIN usuarios u ON t.empleado_id = u.id
        WHERE t.empleado_id = ?
        ORDER BY t.fecha_creacion DESC
        LIMIT 10
        `;
        params.push(req.session.userId);
    } else if (req.session.rol.toLowerCase() === 'técnico') {
        // Si es técnico, obtiene solo los tickets asignados a él
        consulta = `
        SELECT t.id, t.nombre_problemas, t.prioridad, 
               u.nombre AS nombre_empleado, t.estado, 
               DATE_FORMAT(t.fecha_creacion, '%Y/%m/%d') AS fecha_creacion
        FROM tickets t
        JOIN usuarios u ON t.empleado_id = u.id
        WHERE t.tecnico_id = ?
        ORDER BY t.fecha_creacion DESC
        LIMIT 10
        `;
        params.push(req.session.userId);
    }

    // Ejecutar la consulta con los parámetros correctos
    connection.query(consulta, params, function (error, resultados) {
        if (error) {
            console.error("Error al obtener los tickets:", error);
            res.status(500).send("Error al obtener los datos.");
        } else {
            res.render("creacionticket", { 
                nombre: req.session.user, 
                titulo: "Creación de Ticket",
                tickets: resultados,
                rol: req.session.rol
            });
        }
    });
});




app.get("/buscar", function (req, res) {
    if (!req.session.userId) {
        return res.redirect("/login"); // Redirige al login si la sesión no está activa
    }

    let termino = req.query.q;

    let consulta = `
        SELECT t.id, t.nombre_problemas, t.prioridad, 
               u.nombre AS nombre_empleado, t.estado, 
               DATE_FORMAT(t.fecha_creacion, '%Y/%m/%d') AS fecha_creacion
        FROM tickets t
        JOIN usuarios u ON t.empleado_id = u.id
        WHERE t.nombre_problemas LIKE ? OR u.nombre LIKE ?
        ORDER BY t.fecha_creacion DESC
        LIMIT 10
    `;

    let parametro = `%${termino}%`;

    connection.query(consulta, [parametro, parametro], function (error, resultados) {
        if (error) {
            console.error("Error al buscar los tickets:", error);
            res.status(500).send("Error al obtener los datos.");
        } else {
            res.render("creacionticket", { 
                nombre: req.session.user,  // Asegurar que el usuario sigue en sesión
                titulo: "Principal",
                tickets: resultados,
                rol: req.session.rol // Pasar el rol para que el menú no desaparezca
            });
        }
    });
});


//ruta "acerca de"
app.get("/perfil",(req,res)=>{
    res.render("perfil",{titulo: "Perfil"})
})

///Metodo post para guardar datos en la base de datos de tickets
app.post("/guardar", function(req,res){
    const datos = req.body;

    let id = req.session.userId; // Se usa el ID del usuario en sesión
    let nom_problema = datos.nombre_problema;
    let descrip = datos.descripcion;
    let priori = datos.prioridad;
    let estado_ticket = 'Pendiente';
    let fecha = datos.fecha_creacion;

    let registrar = "INSERT INTO tickets (empleado_id, nombre_problemas, descripcion, prioridad, estado, fecha_creacion) VALUES ('"+id+"','"+nom_problema+"','"+descrip+"','"+priori+"','"+estado_ticket+"','"+fecha+"' )";
    connection.query(registrar, function(error){
        if (error) {
            console.error("Error al insertar datos:", error);
            res.status(500).send("Error al guardar los datos.");
        } else {
            console.log("Datos Salmacenados correctamente");
  // Obtener los correos de los administradores
  let consultaAdminEmails = "SELECT email FROM usuarios WHERE rol = 'Administrador'";

  connection.query(consultaAdminEmails, function(error, resultados) {
      if (error) {
          console.error("Error al obtener los correos de los administradores:", error);
      } else {
          if (resultados.length > 0) {
              let emailsAdmin = resultados.map(user => user.email); // Lista de correos de administradores

              // Configurar el correo
              let mailOptions = {
                  from: process.env.EMAIL_USER,
                  to: emailsAdmin, // Enviar solo a los administradores
                  subject: "Nuevo Ticket Creado",
                  text: `Hola, se ha creado un nuevo ticket con los siguientes datos:\n\n` +
                        `Problema: ${nom_problema}\n` +
                        `Descripción: ${descrip}\n` +
                        `Prioridad: ${priori}\n` +
                        `Fecha de Creación: ${fecha}\n\n` +
                        `Por favor revisa el sistema para más detalles.`
              };

              // Enviar el correo
              transporter.sendMail(mailOptions, function(error, info) {
                  if (error) {
                      console.error("Error al enviar el correo:", error);
                  } else {
                      console.log("Correo enviado a administradores: " + emailsAdmin.join(", "));
                  }
              });
          }
      }
  });
                    res.redirect("/creacionticket"); // O res.send("Datos guardados correctamente.");
        }
    });
});

// Ruta para mostrar la página de recuperación de contraseña
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { titulo: "Recuperar Contraseña" });
});

///////////////rutas de user ejs dani/////////////
// resgistro de usuarios sql
app.post("/validar", async function(req,res){
    const datos = req.body;

    let nombre = datos.name;
    let usuario = datos.name_user;
    let correo = datos.email;
    let password = datos.pass;
    let rol = datos.rol;

    const saltRounds = 10;
    const hashedPass = await bcrypt.hash(password, saltRounds);

    let registrar = "INSERT INTO usuarios (nombre, nombre_usuario, email, password, rol) VALUES (?,?,?,?,?)";

    connection.query(registrar, [nombre, usuario, correo, hashedPass, rol],async function(error, results){
        if(error){
            console.error("Error al insertar en MYSQL:", error);
            return res.status(500).json({mensaje: "Error al registrar el usuario en MySQL"});
        };

        // registro en mongo
        try{
            const nuevoUsuario = UserMongo({
                nombre_usuario: usuario,
                roles: rol,
                correo: correo,
                password: hashedPass
            });
            await nuevoUsuario.save();
            console.log("Usuario registro en MongoDb");
            res.redirect("/user");

            // res.status(201).json({
            //     mensaje: "Usuario resgistrado exitosamente en ambas bases de datos",
            //     mysql_id: results.insertId,
            //     mongo_id: nuevoUsuario._id
            // });
        }catch(error){
            console.error("Error al insertar en MongoDB", error);
            res.status(500).json({mensaje: "Error al registrar el usuario en MongoDB"});
        }
    });
});

//ruta de user , tabla de registro
app.get('/user',function(req, res) {

    let consulta = `SELECT * FROM usuarios`;

    connection.query(consulta, function(err, results) {
        if(err){
            console.error('Error en la consulta:', err);
            return res.send('Error en la consulta');
        }else{
            res.render("user", {
            nombre:"Daniela VM",
            titulo:"Usuario registrados de la empresa", 
            data: results});
        }
        
    })
})


// ruta de editar
app.put('/actualizar/:id', async(req, res) =>{
    const {id} = req.params;
    const {name, name_user, email, rol} = req.body;

    try{
        const query = "UPDATE usuarios SET nombre = ?, nombre_usuario = ?, email = ?, rol = ? WHERE id = ?";
        const values = [name,name_user, email, rol, id];

        connection.query(query, values, (error, results) => {
            if(error){
                console.error("Error al actulizar usuario:", error);
                return res.status(500).json({mensaje:"Error en el servidro"});
            }
        })
        
        res.json({ mensaje: "Usuario actulizado corectamente"});
    }catch(error){
        console.error("Error al actualizar usuario:", error);
        res.status(500).json({mensaje: "Error en el servidor"});
    }
})

/*CODIGO DE LOGIN DE JENNIFER*/ 

// Ruta para manejar la autenticación de usuario
app.post('/inicioUsuario', async (req, res) => {
    const { name, pass } = req.body;

    try {
        // 1️⃣ Buscar el usuario en la base de datos
        connection.query(
            'SELECT id, nombre_usuario, password, rol FROM usuarios WHERE nombre_usuario = ?',
            [name], 
            async (error, results) => {
                if (error) {
                    console.error('❌ Error en la consulta SQL:', error);
                    return res.status(500).send('Error en el servidor.');
                }

                console.log('🔍 Resultados de la consulta:', results); 

                // 2️⃣ Verificar si el usuario existe
                if (results.length === 0) {
                    console.warn('⚠ Usuario no encontrado');
                    return res.status(404).render('404', { titulo: 'Error', msg: 'Usuario no existe' });
                }

                const usuario = results[0];
                console.log(`✅ Usuario encontrado - ID: ${usuario.id}, Nombre: ${usuario.nombre_usuario}, Rol: ${usuario.rol}`);

                // 3️⃣ Verificación de contraseña
                const passwordMatch = await bcrypt.compare(pass, usuario.password);
                if (!passwordMatch) {
                    console.warn('⚠ Contraseña incorrecta');
                    return res.status(401).render('404', { titulo: 'Error', msg: 'Contraseña incorrecta' });
                }

                // 4️⃣ Guardar usuario en la sesión
                req.session.userId = usuario.id;
                req.session.user = usuario.nombre_usuario;
                req.session.rol = usuario.rol.toLowerCase(); // Normalizamos el rol en minúsculas

                console.log(`🔐 Sesión iniciada - ID: ${req.session.userId}, Usuario: ${req.session.user}, Rol: ${req.session.rol}`);

                // 5️⃣ Redirigir según el rol del usuario
                switch (req.session.rol) {
                    case 'administrador':
                        return res.redirect('user');  // Redirige a la ruta de administración
                    case 'empleado':
                        return res.redirect('creacionticket'); // Redirige al panel del empleado
                    case 'tecnico':
                        return res.redirect('tecnico'); // Redirige al panel del técnico
                    default:
                        console.error('❌ Rol no autorizado:', req.session.rol);
                        return res.status(403).render('404', { titulo: 'Error', msg: 'Rol no autorizado' });
                }
            }
        );        
    } catch (err) {
        console.error('❌ Error en el servidor:', err);
        if (!res.headersSent) {
            return res.status(500).send('Error en el servidor: ' + err.message);
        }
    }
});

// Ruta para enviar correo de recuperación de contraseña
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const usuario = await UserMongo.findOne({ correo: email });

    if (!usuario) {
      return res.status(404).send('Correo no encontrado');
    }

    const enlaceRecuperacion = `http://localhost:${port}/reset-password?email=${email}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Recuperación de Contraseña',
      text: `Hemos recibido una solicitud de recuperación de contraseña. Haz clic en el siguiente enlace para restablecer tu contraseña: ${enlaceRecuperacion}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).send('Error al enviar el correo: ' + error);
      }
      res.send('Correo de recuperación enviado');
    });
  } catch (err) {
    res.status(500).send('Error en el servidor: ' + err);
  }
});

// Ruta para restablecer la contraseña
// Ruta para restablecer la contraseña
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        // Buscar usuario por correo en MongoDB
        const usuario = await UserMongo.findOne({ correo: email });

        if (!usuario) {
            return res.status(404).send('Usuario no encontrado');
        }

        // Hashear la nueva contraseña
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Actualizar la contraseña en MongoDB
        usuario.password = hashedPassword;
        await usuario.save();

        // Actualizar la contraseña en MySQL
        const sql = 'UPDATE usuarios SET password = ? WHERE email = ?';
        connection.query(sql, [hashedPassword, email], (err, result) => {
            if (err) {
                console.error('Error al actualizar en MySQL:', err);
                return res.status(500).send('Error al actualizar la contraseña en MySQL');
            }

            // Configurar encabezados para evitar caché
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');

            // Cerrar sesión del usuario y eliminar la cookie de sesión
            req.session.destroy(() => {
                res.clearCookie('connect.sid'); // Eliminar cookie de sesión si se usa Express Session
                res.send('Contraseña actualizada con éxito. Vuelve a iniciar sesión.');
            });
        });

    } catch (err) {
        res.status(500).send('Error en el servidor: ' + err);
    }
});



  app.get('/reset-password', (req, res) => {
    const email = req.query.email;
  
    if (!email) {
      return res.status(400).send("Falta el parámetro 'email' en la URL.");
    }
  
    res.render('reset-password', { email, titulo: "Restablecer Contraseña" });
  });
  

//ruta de tickets para asignar tecnico --jocelyne--
app.get("/administrador", (req, res) => {
 
    const getPendientes = "SELECT COUNT(*) AS total FROM tickets WHERE estado = 'Pendiente'";
    const getAsignados = "SELECT COUNT(*) AS total FROM tickets WHERE estado = 'Asignado'";
    const getResueltos = "SELECT COUNT(*) AS total FROM tickets WHERE estado = 'Resuelto'";

    
    const getTecnicos = `
        SELECT u.id AS tecnico_id, u.nombre, 
               COALESCE(a.estado, 'Sin asignar') AS estado,
               a.fecha_asignacion
        FROM usuarios u
        LEFT JOIN asignaciones a ON u.id = a.tecnico_id
        WHERE u.rol = 'Tecnico'
        ORDER BY a.fecha_asignacion DESC;
    `;

  
    connection.query(getPendientes, (err, pendientesResult) => {
        if (err) {
            console.error("Error al obtener tickets pendientes:", err);
            return res.status(500).send("Error interno del servidor");
        }

        connection.query(getAsignados, (err, asignadosResult) => {
            if (err) {
                console.error("Error al obtener tickets asignados:", err);
                return res.status(500).send("Error interno del servidor");
            }

            connection.query(getResueltos, (err, resueltosResult) => {
                if (err) {
                    console.error("Error al obtener tickets resueltos:", err);
                    return res.status(500).send("Error interno del servidor");
                }

                connection.query(getTecnicos, (err, tecnicosResult) => {
                    if (err) {
                        console.error("Error al obtener los técnicos:", err);
                        return res.status(500).send("Error interno del servidor");
                    }

                   
                    //console.log("Datos de técnicos:", tecnicosResult);

                 
                    res.render("administrador", {
                        titulo: "Panel de Administración",
                        totalPendientes: pendientesResult[0].total,
                        totalAsignados: asignadosResult[0].total,
                        totalResueltos: resueltosResult[0].total,
                        tecnicos: tecnicosResult
                    });
                });
            });
        });
    });
});

app.get("/ticket", (req, res) => {
    const getTickets = `
    SELECT t.*, u.nombre AS empleado
    FROM tickets t
    LEFT JOIN usuarios u ON t.empleado_id = u.id
    WHERE t.estado = 'Pendiente'
    ORDER BY t.prioridad DESC, t.fecha_creacion DESC;
  `;
  
    const getTecnicos = `SELECT id, nombre FROM usuarios WHERE rol = 'Tecnico'`;

    connection.query(getTickets, (err, ticketsResult) => {
        if (err) {
            console.error("Error al obtener los tickets:", err);
            return res.status(500).send("Error al obtener los tickets.");
        }

        connection.query(getTecnicos, (err, tecnicosResult) => {
            if (err) {
                console.error("Error al obtener técnicos:", err);
                return res.status(500).send("Error al obtener técnicos.");
            }

            // Formateamos la fecha para cada ticket
            ticketsResult.forEach(ticket => {
                ticket.fecha_creacion = ticket.fecha_creacion.toISOString().split('T')[0];
            });

            res.render("ticket", {
                titulo: "Revisión de Tickets",
                tickets: ticketsResult, // Enviamos una lista de tickets
                tecnicos: tecnicosResult
            });
        });
    });
});

app.get("/ticket/:id", (req, res) => {
    const ticketId = req.params.id;
    const getTicketDetails = `
        SELECT t.*, u.nombre AS empleado
        FROM tickets t
        LEFT JOIN usuarios u ON t.empleado_id = u.id
        WHERE t.id = ?;
    `;

    connection.query(getTicketDetails, [ticketId], (err, result) => {
        if (err) {
            console.error("Error al obtener los detalles del ticket:", err);
            return res.status(500).send("Error al obtener los detalles del ticket.");
        }

        if (result.length > 0) {
            result[0].fecha_creacion = result[0].fecha_creacion.toISOString().split('T')[0]; // Formato YYYY-MM-DD
            return res.json(result[0]); // Devuelve el primer ticket encontrado en formato JSON
        } else {
            return res.status(404).send("Ticket no encontrado.");
        }
    });
});

app.get('/tecnico', (req, res) => {
    // Verificar que el usuario esté autenticado y que sea un técnico
    if (!req.session.userId || req.session.rol !== 'tecnico') {
        return res.redirect('/login');  // Redirige al login si no es un técnico o no está autenticado
    }

    const tecnicoId = req.session.userId;  // Obtiene el ID del técnico desde la sesión

    // Consulta SQL para obtener los tickets asignados al técnico
    const query = `
        SELECT t.id, t.nombre_problemas, t.descripcion, t.prioridad, a.estado, t.fecha_creacion, a.fecha_asignacion
        FROM tickets t
        INNER JOIN asignaciones a ON t.id = a.ticket_id
        WHERE a.tecnico_id = ?;
    `;

    // Ejecutar la consulta para obtener los tickets asignados
    connection.query(query, [tecnicoId], (err, ticketsResult) => {
        if (err) {
            console.error("Error al obtener los tickets asignados:", err);
            return res.status(500).send("Error al obtener los tickets.");
        }

        // Formatear la fecha de asignación si es necesario
        ticketsResult.forEach(ticket => {
            // Verificar si la fecha de asignación no es null
            if (ticket.fecha_asignacion) {
                ticket.fecha_asignacion = ticket.fecha_asignacion.toISOString().split('T')[0]; // Formato YYYY-MM-DD
            } else {
                ticket.fecha_asignacion = 'No asignado'; // O asignar cualquier valor predeterminado
            }
        });

        // Renderizar la vista 'tecnico' con los tickets asignados
        res.render('tecnico', {
            titulo: 'Panel Técnico',
            tickets: ticketsResult
        });
    });
});

app.put('/ticket/completar/:id', (req, res) => {
    const ticketId = req.params.id;  // Obtener el ticket.id desde la URL
    const { estado } = req.body;  // El estado (completado) lo obtenemos del cuerpo de la solicitud

    // Actualizar el estado del ticket en la base de datos
    connection.query('UPDATE tickets SET estado = ? WHERE id = ?', [estado, ticketId], (error, results) => {
        if (error) {
            console.error('Error al actualizar el estado del ticket:', error);
            return res.status(500).json({ success: false, message: 'Error al actualizar el ticket' });
        }

        // También puedes actualizar la tabla de asignaciones si es necesario
        connection.query('UPDATE asignaciones SET estado = ? WHERE ticket_id = ?', [estado, ticketId], (assignError) => {
            if (assignError) {
                console.error('Error al actualizar el estado en asignaciones:', assignError);
                return res.status(500).json({ success: false, message: 'Error al actualizar asignaciones' });
            }

            // Si todo salió bien, devolver una respuesta exitosa
            res.json({ success: true });
        });
    });
});




app.post("/asignar/:id", (req, res) => {
    const ticketId = req.params.id;      
    const tecnicoId = req.body.tecnico_id; 

    if (!tecnicoId) {
        console.error("Error: tecnico_id no definido");
        return res.status(400).send("Error: No se recibió el técnico.");
    }

   
    const insertAsignacion = `INSERT INTO asignaciones (ticket_id, tecnico_id, fecha_asignacion) VALUES (?, ?, CURDATE())`;

    connection.query(insertAsignacion, [ticketId, tecnicoId], (err) => {
        if (err) {
            console.error("Error al registrar la asignación:", err);
            return res.status(500).send("Error al registrar la asignación.");
        }

        
        const updateTicket = `UPDATE tickets SET estado = 'Asignado' WHERE id = ?`;
        connection.query(updateTicket, [ticketId], (err) => {
            if (err) {
                console.error("Error al actualizar el ticket:", err);
                return res.status(500).send("Error al actualizar el estado del ticket.");
            }

           // console.log(`Asignación guardada: Ticket ${ticketId} asignado al técnico ${tecnicoId}`);
            res.redirect("/ticket");
        });
    });
});
////////////////////////////////////

// ruta para eliminar empleados
app.delete('/eliminar/:id', async (req, res) =>{
    const { id } = req.params;

    try{
        const consultaCorreo = "SELECT email From usuarios WHERE id = ?";
        connection.query(consultaCorreo, [id], async (error, results) => {
            if(error){
                console.error("Error al obtener correo:", error);
                return res.status(500).json({ mensaje: "Error en el servidor"});
            }
            if(results.length === 0){
                return res.status(404).json({ mensaje: "Usuario no encontrado"});
            }

            const correoUsuario = results[0].email;

            const eliminarMySQL = "DELETE FROM usuarios WHERE id = ?";
            connection.query(eliminarMySQL, [id], async (error, results) => {
                if(error){
                    console.error("Error al eliminar en MySQL:", error);
                    return res.status(500).json({mensaje: "Error al eliminar en MySQL"});
                }

                try{
                    const resultadoMongo = await UserMongo.findOneAndDelete({correo: correoUsuario});

                    if(!resultadoMongo){
                        console.warn("Usuario no encontrado en MongoDB");
                    }
                    return res.json({mensaje: "Usuario eliminado correctamente en ambas bases de datos"});
                }catch(error){
                    console.error("Error al eliminar en MongoDB:", error);
                    return res.status(500).json({mensaje:"Error al eliminar en MongoDB"});
                }
            });
        });
    }catch(error){
        console.error("Error general:", error);
        res.status(500).json({mensaje: "Error en el servidor"});
    }
});

/*VER QUE USUARIOS HAN INICIADO SESION*/
app.get("/verificar-sesion", (req, res) => {
    if (req.session.userId && req.session.user) {
        console.log(`ID: ${req.session.userId}, Usuario: ${req.session.user}, Rol: ${req.session.rol}`);
        return res.send(`Usuario autenticado - ID: ${req.session.userId}, Nombre: ${req.session.user}, Rol: ${req.session.rol}`);
    } else {
        console.log("No hay sesión activa.");
        return res.send("No has iniciado sesión.");
    }
});

/*VISTA DEL TECNICO*/ 

//CIERRE DE SESION
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Error al cerrar sesión:', err);
            return res.status(500).send('Error al cerrar sesión');
        }
        console.log('🔐 Sesión cerrada correctamente');
        res.redirect('/login'); // Redirige a la página de inicio de sesión
    });
});

//rutas para el manejo de errores
app.use((req,res)=>{
    res.status(400).render("404",{titulo: "pagina no encontrada"})
})

//Iniciar el Servidor
// app.listen(port,()=>{
//     console.log(`Servidor en http://localhost:${port}`);
// })

if (process.env.NODE_ENV !== "test") {
  const PORT = process.env.PORT || 5030;
  app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
  });
}

// Exporta app para Jest
module.exports = app;