const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify([]));
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ---------- Acceso de administradores (Gmail + carnet) ----------
const ADMINS_FILE = path.join(__dirname, 'admins.json');
const normCorreo = v => String(v || '').trim().toLowerCase();
const normCarnet = v => String(v || '').replace(/\D/g, ''); // solo dígitos: "1424575", "1424575 LP" -> 1424575
const esGmail = v => /^[^\s@]+@gmail\.com$/.test(v);

function leerAdmins() {
  try { return JSON.parse(fs.readFileSync(ADMINS_FILE, 'utf8')); } catch (e) { return []; }
}

const SESION_MS = 8 * 60 * 60 * 1000;          // la sesión dura 8 horas
const sesiones = new Map();                     // token -> { correo, expira }
const intentos = new Map();                     // ip -> { n, hasta }
const MAX_INTENTOS = 5, BLOQUEO_MS = 15 * 60 * 1000;

app.post('/api/admin/login', (req, res) => {
  const ip = req.ip;
  const reg = intentos.get(ip);
  if (reg && reg.n >= MAX_INTENTOS && Date.now() < reg.hasta) {
    return res.status(429).json({ success: false, message: 'Demasiados intentos. Espera unos minutos e intenta de nuevo.' });
  }

  const correo = normCorreo(req.body.correo);
  const carnet = normCarnet(req.body.carnet);
  const admin = esGmail(correo) && carnet
    ? leerAdmins().find(a => normCorreo(a.correo) === correo && normCarnet(a.carnet) === carnet)
    : null;

  if (!admin) {
    const n = (reg && Date.now() < reg.hasta ? reg.n : 0) + 1;
    intentos.set(ip, { n, hasta: Date.now() + BLOQUEO_MS });
    return res.status(401).json({ success: false, message: 'Correo o carnet incorrecto.' });
  }

  intentos.delete(ip);
  const token = crypto.randomBytes(32).toString('hex');
  sesiones.set(token, { correo, expira: Date.now() + SESION_MS });
  res.json({ success: true, token, nombre: admin.nombre || correo });
});

function requireAdmin(req, res, next) {
  const token = (req.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const ses = sesiones.get(token);
  if (!ses || Date.now() > ses.expira) {
    sesiones.delete(token);
    return res.status(401).json({ success: false, message: 'Sesión no válida.' });
  }
  next();
}

app.post('/api/admin/logout', (req, res) => {
  sesiones.delete((req.get('Authorization') || '').replace(/^Bearer\s+/i, ''));
  res.json({ success: true });
});

app.post('/api/postular', (req, res) => {
  const { nombre, carnet, telefono, formacion, experiencia, categoria, puesto, detalle_especifico } = req.body;
  
  const postulaciones = readDB();
  const nuevaPostulacion = {
    id: postulaciones.reduce((m, p) => Math.max(m, p.id), 0) + 1,
    nombre: String(nombre || 'Sin nombre').slice(0, 120),
    carnet: String(carnet || 'Sin carnet').slice(0, 30),
    telefono: String(telefono || 'Sin teléfono').slice(0, 30),
    formacion: String(formacion || 'Sin formación').slice(0, 40),
    experiencia: experiencia || 0,
    categoria: categoria || 'General',
    puesto: puesto || 'General',
    detalle_especifico: String(detalle_especifico || 'Sin detalles').slice(0, 4000),
    estado: 'Nuevo',
    fecha: new Date().toISOString()
  };

  postulaciones.push(nuevaPostulacion);
  writeDB(postulaciones);

  res.json({ success: true, id: nuevaPostulacion.id });
});

app.get('/api/admin/postulaciones', requireAdmin, (req, res) => {
  const postulaciones = readDB();
  postulaciones.sort((a, b) => new Date(b.fecha) - new Date(a.fecha));
  res.json({ success: true, data: postulaciones });
});

app.patch('/api/admin/postulaciones/:id', requireAdmin, (req, res) => {
  const postulaciones = readDB();
  const item = postulaciones.find(p => p.id === parseInt(req.params.id));
  if (!item) return res.status(404).json({ success: false });
  if (req.body.estado !== undefined) item.estado = req.body.estado;
  if (req.body.notas !== undefined) item.notas = String(req.body.notas).slice(0, 2000);
  writeDB(postulaciones);
  res.json({ success: true });
});

app.delete('/api/admin/postulaciones/:id', requireAdmin, (req, res) => {
  const postulaciones = readDB();
  const id = parseInt(req.params.id);
  const resto = postulaciones.filter(p => p.id !== id);
  if (resto.length === postulaciones.length) return res.status(404).json({ success: false });
  writeDB(resto);
  res.json({ success: true });
});

// ---------- Limpieza automática de postulaciones ----------
// Configuración editable en config.json (se crea sola la primera vez).
const CONFIG_FILE = path.join(__dirname, 'config.json');
const APROBADOS_FILE = path.join(__dirname, 'aprobados.json');
const CONFIG_DEFECTO = {
  limpiezaAutomatica: true,        // false = nunca borra nada solo
  diasRetencion: 30,               // días que se conserva una postulación desde que llegó
  estadosAprobados: ['Contratado'],// estados que se guardan en aprobados.json antes de borrar
  estadosProtegidos: [],           // estados que NUNCA se borran solos (ej. ['Entrevista'])
  revisarCadaMinutos: 60           // cada cuánto revisa el servidor
};

function leerConfig() {
  let c = {};
  if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(CONFIG_DEFECTO, null, 2));
  } else {
    try { c = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch (e) { console.error('config.json inválido, uso valores por defecto'); }
  }
  return { ...CONFIG_DEFECTO, ...c };
}

function leerAprobados() {
  try { return JSON.parse(fs.readFileSync(APROBADOS_FILE, 'utf8')); } catch (e) { return []; }
}

// Escritura segura: archivo temporal + renombrar, así un corte a medias no corrompe el .json
function escribirJSON(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}

function limpiarPostulaciones() {
  const cfg = leerConfig();
  const limite = Date.now() - cfg.diasRetencion * 24 * 60 * 60 * 1000;
  const postulaciones = readDB();

  const vencidas = [], vigentes = [];
  postulaciones.forEach(p => {
    const t = new Date(p.fecha).getTime();
    const estado = p.estado || 'Nuevo';
    const vencida = !isNaN(t) && t < limite && !cfg.estadosProtegidos.includes(estado);
    (vencida ? vencidas : vigentes).push(p);
  });
  if (!vencidas.length) return { borrados: 0, archivados: 0 };

  // 1) Primero se guardan los aprobados; solo si eso salió bien se borra de la base
  const aprobados = vencidas.filter(p => cfg.estadosAprobados.includes(p.estado || 'Nuevo'));
  if (aprobados.length) {
    const archivo = leerAprobados();
    const ya = new Set(archivo.map(a => a.carnet + '|' + a.fecha));
    const ahora = new Date().toISOString();
    aprobados.forEach(p => {
      if (!ya.has(p.carnet + '|' + p.fecha)) archivo.push({ ...p, archivado: ahora });
    });
    escribirJSON(APROBADOS_FILE, archivo);
  }

  // 2) Se borra el resto de la lista
  writeDB(vigentes);
  console.log(`Limpieza: ${vencidas.length} postulaciones borradas, ${aprobados.length} aprobadas guardadas en aprobados.json`);
  return { borrados: vencidas.length, archivados: aprobados.length };
}

app.get('/api/admin/config-limpieza', requireAdmin, (req, res) => {
  const c = leerConfig();
  res.json({ success: true, activa: c.limpiezaAutomatica, dias: c.diasRetencion, estados: c.estadosAprobados, aprobados: leerAprobados().length });
});

app.get('/api/admin/aprobados', requireAdmin, (req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename="aprobados.json"');
  res.json(leerAprobados());
});

app.post('/api/admin/limpiar-ahora', requireAdmin, (req, res) => {
  res.json({ success: true, ...limpiarPostulaciones() });
});

// Mensajes del formulario de contacto
const CONTACT_FILE = path.join(__dirname, 'contactos.json');
app.post('/api/contacto', (req, res) => {
  const { nombre, correo, asunto, mensaje } = req.body;
  if (!nombre || !correo || !mensaje) return res.status(400).json({ success: false });
  let lista = [];
  try { lista = JSON.parse(fs.readFileSync(CONTACT_FILE, 'utf8')); } catch (e) {}
  lista.push({
    id: lista.length ? lista[lista.length - 1].id + 1 : 1,
    nombre: String(nombre).slice(0, 120),
    correo: String(correo).slice(0, 160),
    asunto: String(asunto || '').slice(0, 160),
    mensaje: String(mensaje).slice(0, 3000),
    fecha: new Date().toISOString()
  });
  fs.writeFileSync(CONTACT_FILE, JSON.stringify(lista, null, 2));
  res.json({ success: true });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor activo en http://localhost:${PORT} y en http://192.168.1.106:${PORT}`);
  const cfg = leerConfig();
  if (cfg.limpiezaAutomatica) {
    const correr = () => { try { limpiarPostulaciones(); } catch (e) { console.error('Error en la limpieza:', e); } };
    correr(); // al arrancar
    setInterval(correr, Math.max(1, cfg.revisarCadaMinutos) * 60 * 1000);
  }
});
 