const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path'); // Importar path para servir arquivos estáticos
const app = express();
const User = require('./models/User');
const CollectionPoint = require('./models/CollectionPoint');
const Appointment = require('./models/Appointment')
require('dotenv').config();

// Configuração do CORS
app.use(cors({
    origin: 'https://22ff14e4-7e09-49ba-a390-f869e91b702e-00-2svojrkn9rkle.janeway.replit.dev', //Qualquer Origem
    credentials: true
}));

// Configurar o parser de JSON e cookies
app.use(express.json());
app.use(cookieParser());

// Conectar ao MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Conectado ao MongoDB'))
.catch(err => console.error('Erro ao conectar ao MongoDB', err));

// Middleware para verificar o token
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Acesso negado' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Token inválido' });
        req.user = user; // O ID do usuário deve estar aqui
        next();
    });
};


// Middleware para redirecionar usuários logados da página de login para o perfil
const redirectIfLoggedIn = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err) => {
            if (!err) return res.redirect('/profile.html');
            next();
        });
    } else {
        next();
    }
};


// Middleware para redirecionar usuários não autenticados da página de perfil para a página de login
const redirectIfNotLoggedIn = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.redirect('/');
    jwt.verify(token, process.env.JWT_SECRET, (err) => {
        if (err) return res.redirect('/');
        next();
    });
};


// Rota de registro
app.post('/api/register', async (req, res) => {
    const { name, email, address, password, role } = req.body;

    // Verifica se o papel (role) é válido
    if (!['donor', 'collector'].includes(role)) {
        return res.status(400).json({ success: false, message: 'Tipo de usuário inválido' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Usuário já existe' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, address, password: hashedPassword, role });
        await newUser.save();
        res.status(201).json({ success: true, message: 'Usuário registrado com sucesso!' });
    } catch (error) {
        console.error('Erro ao registrar usuário:', error);
        res.status(500).json({ success: false, message: 'Erro ao registrar usuário' });
    }
});


// Rota de login com JWT
app.post('/api/login', async (req, res) => {
    const { email, password, role } = req.body; 
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Usuário não encontrado' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Senha incorreta' });
        }

        // Verificar se o papel do usuário corresponde ao papel informado na solicitação
        if (user.role !== role) {
            return res.status(403).json({ success: false, message: 'Tipo de usuário errado' });
        }

        // Incluindo o ID do usuário no payload do token
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'None', secure: true });
        res.json({ success: true, token });
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        res.status(500).json({ success: false, message: 'Erro ao fazer login' });
    }
});


// Rota para obter dados do usuário
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
        res.json({ success: true, user });
    } catch (error) {
        console.error('Erro ao obter perfil do usuário:', error);
        res.status(500).json({ success: false, message: 'Erro ao obter perfil do usuário' });
    }
});


// Rota de logout
app.post('/api/logout', (req, res) => {
    res.cookie('token', '', { httpOnly: true, expires: new Date(0), sameSite: 'None', secure: true });
    res.json({ success: true });
});

// Rota de registro de vinculo doador - coletor
app.post('/api/appointment', async (req, res) => {
    const {  collectorUserId,
        collectorName,
        collectorContact,
        collectorEmail,
        collectorAddress,
        donorUserId,
        donorName,
        donorContact,
        donorEmail } = req.body;


    try {
        const newAppointment = new Appointment({ collectorUserId,
            collectorName,
            collectorContact,
            collectorEmail,
            collectorAddress,
            donorUserId,
            donorName,
            donorContact,
            donorEmail });

        await newAppointment.save();
        res.status(201).json({ success: true, message: 'Sua solicitação de coleta foi registrada com sucesso!' });
    } catch (error) {
        console.error('Erro ao registrar a solicitação de coleta:', error);
        res.status(500).json({ success: false, message: 'Erro ao registrar a solicitação de coleta' });
    }
});

/* app.post('/api/collectionpoint', async (req, res) => {
    const { userId, name, contact, email, address, material } = req.body;

    try {
        // Encontra o usuário pelo userId
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
        }

        // Cria o novo ponto de coleta
        const newCollectionPoint = {
            name,
            contact,
            email,
            address,
            material
        };

        // Adiciona o novo ponto de coleta ao array de collectionPoints
        user.collectionPoints.push(newCollectionPoint);

        // Salva as mudanças no banco de dados
        await user.save();

        res.status(201).json({ success: true, message: 'Seu ponto de coleta foi registrado com sucesso!', collectionPoints: user.collectionPoints });
    } catch (error) {
        console.error('Erro ao registrar o ponto de coleta:', error);
        res.status(500).json({ success: false, message: 'Erro ao registrar o ponto de coleta' });
    }
});
 */

//Criar ponto de coleta
app.post('/api/collectionpoint', async (req, res) => {
    const { userId, name, contact, email, address, material } = req.body;


    try {
        const newCollectionPoint = new CollectionPoint({ userId, name, contact, email, address, material });
        await newCollectionPoint.save();
        res.status(201).json({ success: true, message: 'Seu ponto de coleta foi registrado com sucesso!' });
    } catch (error) {
        console.error('Erro ao registrar o ponto de coleta:', error);
        res.status(500).json({ success: false, message: 'Erro ao registrar o ponto de coleta' });
    }
});


// Rota para obter dados de todos os coletores
app.get('/api/allcollectionpoints', authenticateToken, async (req, res) => {
    try {
        // Buscar todos os documentos da coleção CollectionPoint
        const collectionPoints = await CollectionPoint.find();

        // Retornar os pontos de coleta encontrados
        res.status(200).json({ success: true, collectionPoints });
    } catch (error) {
        console.error('Erro ao buscar pontos de coleta:', error);
        res.status(500).json({ success: false, message: 'Erro ao buscar pontos de coleta' });
    }
});


app.put('/api/users/:id', async (req, res) => {
    const userId = req.params.id; //Passar id como parâmetro da consulta
    const { name, email, address, password, role } = req.body;

    try {
        // Encontrar o usuário pelo ID e atualizar os campos fornecidos
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { name, email, address, password, role },
            { new: true, runValidators: true } // new: true retorna o documento atualizado, runValidators: true aplica as validações
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
        }

        res.status(200).json({ success: true, message: 'Usuário atualizado com sucesso', user: updatedUser });
    } catch (error) {
        console.error('Erro ao atualizar o usuário:', error);
        res.status(500).json({ success: false, message: 'Erro ao atualizar o usuário' });
    }
});


// Servir arquivos estáticos da pasta onde os arquivos estão localizados
app.use(express.static(path.join(__dirname, 'cadastro-usuarios')));

// Rota para servir a página principal e de perfil
app.get('/profile.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'cadastro-usuarios', 'profile.html'));
});

// Rota de login, redireciona usuários logados para o perfil
app.get('/', redirectIfLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'cadastro-usuarios', 'index.html'));
});

// Rota para todas as outras páginas protegidas
app.get('*', redirectIfNotLoggedIn, (req, res) => {
    if (req.path.endsWith('.html')) {
        res.redirect('/');
    } else {
        res.sendFile(path.join(__dirname, 'cadastro-usuarios', req.path));
    }
});

// Iniciar o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
