const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');


const JWT_SECRET_KEY = "6K!U?ñxiYk7T7P7Q7pZ$Aa~Y2"; 

const pool = new Pool({
  host: "localhost",
  user: "postgres",
  password: "261295.",
  database: "softjobs",
  allowExitOnIdle: true,
  port: 5432,
});

const verificarCredencialesMiddleware = (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Se requieren email y contraseña" });
  }
  next();
};

const validarTokenMiddleware = (req, res, next) => {
  const token = req.header("Authorization")?.split("Bearer ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ message: "Acceso denegado: Token no proporcionado" });
  }

  try {
    
    const payload = jwt.verify(token, JWT_SECRET_KEY); 
    req.usuario = payload;
    next();
  } catch (error) {
    console.error("Error de validación de token:", error);
    res.status(401).json({ message: "Acceso denegado: Token inválido" });
  }
};

const registrarConsultaMiddleware = (req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`); 
  next();
};

const verificarCredenciales = async (email, password) => {
  const consulta = "SELECT * FROM usuarios WHERE email = $1 AND password = $2";
  const values = [email, password];
  const { rowCount } = await pool.query(consulta, values);
  if (!rowCount)
    throw {
      code: 404,
      message: "No se encontro ningún usuario con estas credenciales",
    };
};

const getJobs = async () => {
  const { rows: usuarios } = await pool.query("SELECT * FROM usuarios");
  return usuarios;
};

const ingresarUsuario = async ({ id, email, password, rol, lenguage }) => {
  console.log(email, lenguage, password, rol);
  const passwordEncriptada = bcrypt.hashSync(password);
  password = passwordEncriptada; 
  const consulta =
    "INSERT INTO usuarios (id,email,password, rol, lenguage) VALUES (DEFAULT,$1, $2, $3, $4)";
  const values = [email, passwordEncriptada, rol, lenguage]; 
  await pool.query(consulta, values);
};

module.exports = {
  verificarCredenciales,
  getJobs,
  ingresarUsuario,
  verificarCredencialesMiddleware,
  validarTokenMiddleware,
  registrarConsultaMiddleware,
};
