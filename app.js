require('dotenv').config();
const express = require("express");
const app = express();
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient;
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const baseUrl = process.env.BASE_URL;
const { authenticateToken } = require('./authMiddleware');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/uploads', express.static('uploads'));

// Configurar almacenamiento de archivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    },
});

const upload = multer({ storage: storage });

// * * *  ENDPOINTS PARA USUARIOS * * * 

//Mostrar usuarios
app.get("/usuarios", async (req, res) => {
    const usuarios = await prisma.user.findMany();
    res.json(usuarios);
})
app.get("/usuario/:id", async (req, res) => {
    const { id } = req.params;

    try {
        const usuario = await prisma.user.findUnique({
            where: { id: Number(id) },
        });

        if (!usuario) {
            return res.status(404).json({ message: "Usuario no encontrado." });
        }

        // No enviar la contraseña
        const { password, ...userWithoutPassword } = usuario;

        res.json(userWithoutPassword);
    } catch (error) {
        console.error("Error al obtener el usuario:", error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

//Crear un usuario
app.post('/registrarUsuario', upload.single('photo'), async (req, res) => {
    const { name, email, password } = req.body;
    const photo = req.file ? req.file.path : 'uploads/default_user_img/default_img.jpg';

    try {
        // Validar los datos
        if (!name || !email || !password) {
            return res.status(400).json({ message: "Error. Ingresa todos los datos necesarios." });
        }

        // Verificar que el correo no esté ya registrado
        const usuarioExiste = await prisma.user.findUnique({
            where: { email },
        });
        if (usuarioExiste) {
            return res.status(400).json({ message: "Error. Este correo ya está registrado." });
        }


        // Validar la contraseña
        if (!validator.isStrongPassword(password, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1,
        })) {
            return res.status(400).json({
                message: "La contraseña debe tener mínimo 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial."
            });
        }

        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);
        // Crear el usuario en la base de datos
        const newUser = await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword,
                photo,
            },
        });
        const { password: _, ...userWithoutPassword } = newUser;


        res.status(201).json({
            message: "Usuario registrado correctamente.",
            user: userWithoutPassword,
        });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

//Actualizar usuario
app.put("/actualizarUsuario/:id", authenticateToken, upload.single('photo'), async (req, res) => {
    const { id } = req.params;
    const { name, email, password } = req.body;
    const photo = req.file ? req.file.path : null;

    // Validar que al menos uno de los campos esté presente para actualizar
    if (!name && !email && !password && !photo) {
        return res.status(400).json({ message: "Error. Se debe enviar al menos un dato para actualizar." });
    }

    try {
        const usuarioExistente = await prisma.user.findUnique({
            where: { id: Number(id) },
        });
        if (!usuarioExistente) {
            return res.status(404).json({ message: "Error. Usuario no encontrado." });
        }

        // Crear un objeto con los campos que se desean actualizar
        const updatedData = {};
        if (name) updatedData.name = name;
        if (email) {
            if (!validator.isEmail(email)) {
                return res.status(400).json({ message: "Error. El correo no tiene un formato válido." });
            }

            const emailInUse = await prisma.user.findFirst({
                where: {
                    email,
                    NOT: { id: Number(id) },
                },
            });

            if (emailInUse) {
                return res.status(400).json({ message: "Error. Este correo ya está registrado por otro usuario." });
            }

            updatedData.email = email;
        }
        if (password) {
            updatedData.password = await bcrypt.hash(password, 10);
        }


        if (photo) updatedData.photo = baseUrl + "/" + photo;

        // Actualizar el usuario en la base de datos
        const updatedUser = await prisma.user.update({
            where: { id: Number(id) },
            data: updatedData,
        });

        const { password: _, ...userWithoutPassword } = updatedUser;

        res.status(200).json({
            message: "Usuario actualizado correctamente.",
            user: userWithoutPassword,
        });
    } catch (error) {
        console.error("Error actualizando usuario:", error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

//Eliminar usuario
app.delete("/eliminarUsuario/:id", async (req, res) => {
    const { id } = req.params;
    const eliminar = await prisma.user.delete({
        where: { id: Number(id) }
    });

    res.json("Usuario eliminado");
})

//Iniciar sesion usuario
app.post("/iniciarSesion", async (req, res) => {
    try {
        const { email, password } = req.body;

        //Validar que se haya enviado email y password
        if (!email || !password) {
            return res.status(400).json({ message: "Error. Debes enviar correo y contraseña." });
        }

        //Buscar al usuario por email
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(401).json({ message: "Error. Usuario o contraseña incorrectos." });
        }

        //Verificar que la contraseña encriptada coincida
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Error. Usuario o contraseña incorrectos." });
        }

        const payload = {
            id: user.id,
            email: user.email,
            name: user.name,
            photo: user.photo === 'uploads/default_user_img/default_img.jpg'
                ? `${baseUrl}/${user.photo}`
                : user.photo,
        };

        // Generar el token usando la variable secreto
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({
            message: "Inicio de sesión exitoso.",
            token,
        });
    } catch (error) {
        console.error("Error en el login:", error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

// * * *  ENDPOINTS PARA POSTS * * * 

//Mostrar posts
app.get("/posts", async (req, res) => {
    const posts = await prisma.post.findMany();
    res.json(posts);
})

//CREAR POST
app.post("/crearPost", authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { content, city, country } = req.body;
        const userId = req.user.id;       
        const filePath = req.file?.path;      

        if (!filePath && !content) {
            return res.status(400).json({ message: "Error. Publicacion vacia." });
        }

        const imageUrl = filePath ? `${baseUrl}/${filePath}` : null;

        const nuevoPost = await prisma.post.create({
            data: {
                image: imageUrl,
                content,
                city,
                country,
                user: { connect: { id: userId } }, // relación con modelo User
            },
        });

        res.status(201).json(nuevoPost);
        console.log("PUBLICACION CREADA")
    } catch (err) {
        console.error("Error creando Post:", err);
        res.status(500).json({ message: "Error interno al crear la publicación." });
    }
}
);

//Eliminar post
app.delete("/eliminarPost/:id", async (req, res) => {
    const { id } = req.params;
    const eliminar = await prisma.post.delete({
        where: { id: Number(id) }
    });

    res.json("Post eliminado");
})

app.listen(3000, () => {
    console.log("Servidor corriendo en localhost puerto 3000")
});