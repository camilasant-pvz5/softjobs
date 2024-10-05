const jwt = require("jsonwebtoken");
const express = require("express");
const app = express();
const cors = require("cors");

const {
  getJobs,
  verificarCredenciales,
  ingresarUsuario,
  verificarCredencialesMiddleware,
  validarTokenMiddleware,
  registrarConsultaMiddleware,
} = require("./consultas");

app.listen(3000, console.log("servidor activo"));
app.use(cors());
app.use(express.json());
app.use(registrarConsultaMiddleware);

const JWT_SECRET_KEY = "6K!U?ñxiYk7T7P7Q7pZ$Aa~Y2";

app.post("/login", verificarCredencialesMiddleware, async (req, res) => {
  try {
    const { email, password } = req.body;
    await verificarCredenciales(email, password);
    const token = jwt.sign({ email }, JWT_SECRET_KEY);
    console.log("login token", token);
    res.send(token);
  } catch (error) {
    console.log(error);
    res.status(error.code || 500).send(error);
  }
});

app.get("/usuarios", validarTokenMiddleware, async (req, res) => {
  try {
    const Authorization = req.header("Authorization");
    const token = Authorization.split("Bearer ")[1];
    console.log("token", token);
    const payload = jwt.verify(token, JWT_SECRET_KEY);
    console.log("payload", payload);
    //console.log(req.header("Authorization"));
    const eventos = await getJobs();
    res.json(eventos);
  } catch (error) {
    console.log(error);
    res.status(error.code || 500).send(error);
  }
});

app.post("/usuarios", async (req, res) => {
  try {
    await ingresarUsuario(req.body);
  } catch (error) {
    console.log(error);
    res.status(error.code || 500).send(error);
  }
});