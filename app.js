require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const secret = process.env.SECRET; //Código secreto encontrado no .env para maior segurança
const cors = require('cors');
app.use(cors());

app.use(express.json());

const User = require('./models/User');

app.get('/', (req, res) => {
    res.status(200).json({ msg: 'bem vindo' }); //rota teste
});

app.get('/user/:id', checkToken, async (req, res) => { //rota para acessar api individual de cada usuário com verificação de token
    const id = req.params.id;

    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({ msg: 'usuário não encontrado' });
    }

    res.status(200).json({ user });
});

function checkToken(req, res, next) {
    
    const authHeader = req.headers.authorization; //captando o cabeçalho 
  

    if (!authHeader) {
        return res.status(401).json({ message: 'Token não fornecido.' }); //verificando se há algo no cabeçalho
    }

    const token = authHeader.split(' ')[1]; //captar o token "bearer : 123" 123 seria o token
  

    if (!token) {
        return res.status(401).json({ message: 'Token incorreto.' }); //verifica se o token está correto
    }
  
    jwt.verify(token, secret, (err, decoded) => {
        if (err) {
            console.error('Erro na verificação do token:', err); //erro de verificação do token
            return res.status(403).json({ message: 'Falha na autenticação do token.' });
        }
        req.user = decoded;
        next();
    });
  }


app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body; //captando strings que serão necessárias 

    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório' });
    }
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório' });
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória' });
    }
    if (password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem' });
    }

    const userExist = await User.findOne({ email: email }); //verifica se o o email exite no banco de dados

    if (userExist) {
        return res.status(422).json({ msg: 'Utilize outro email' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: passwordHash,
    });

    try {
        await user.save();
        res.status(201).json({ msg: 'Usuário cadastrado com sucesso!' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: 'Aconteceu algum erro no servidor!' });
    }
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({email: email})

        if (!user) {
            return res.status(404).json({ msg: 'Usuário não encontrado' });
        }
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
            if (!isPasswordCorrect) {
            return res.status(422).json({ msg: 'Senha incorreta' });
        }

     
       
        const token = jwt.sign({ id: user.id, email: user.email }, secret, { expiresIn: '1h' });

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ msg: 'Aconteceu algum erro no servidor!' });
    }
});

app.get('/restricted', checkToken,  (req, res) => {
    res.sendFile(path.join(__dirname, 'views/restricted.html'));
});

const dbUser = process.env.DB_USER;
const dbPassword = process.env.BR_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.nskqgcr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        const PORT = 3001;
        app.listen(PORT, () => {
            console.log(`Servidor rodando na porta ${PORT}`);
        });
    })
    .catch((err) => {
        console.log('não conectou ao banco!', err);
    });
