require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

const cors = require('cors');



// Use o middleware CORS
app.use(cors());


//configuração json response
app.use(express.json())

// Models com usuarios
const User = require('./models/User')

app.get('/', (req, res) =>{
    res.status(200).json({msg: 'bem vindo'})
})

//private route
app.get('/user/:id', checkToken, async(req,res)=>{
    const id = req.params.id

    //checar se o id existe
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg: 'usuário não encontrado'})
    }

    res.status(200).json({user})
})

//verifica token
function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token){
        return res.status(401).json({msg:'Acesso negado!'})
    }

    try{
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()


    }catch(error){
        res.status(400).json({msg: 'Token inválido!'})
    }
}


//registrar usuário
app.post('/auth/register', async(req, res) =>{
    const{name, email, password, confirmpassword} = req.body

    if(!name){
        return res.status(422).json({msg : 'O nome é obrigatório'})
    }
    if(!email){
        return res.status(422).json({msg : 'O email é obrigatório'})
    }
    if(!password){
        return res.status(422).json({msg : 'A senha é obrigatória'})
    }
    if(password !== confirmpassword){
        return res.status(422).json({msg : 'As senhas não conferem'})
    }

    //conferir se o usuário já existe 
    const userExist = await User.findOne({email: email})

    if(userExist){
        return res.status(422).json({msg : 'Utilize outro email'})
    }

    //criar senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)



    //criar usuário
    const user = new User({
        name, 
        email,
        password: passwordHash,
    })

    try{
        await user.save()
        res.status(201).json({msg: 'Usuário cadastrado com sucesso!'})
    }catch(error){
        console.log(error)
        res.status(500).json({msg: 'Aconteceu algum erro no servidor!'})
    }


})

app.post('/auth/login', async(req, res) =>{
    const { email, password} = req.body

    const user = await User.findOne({email: email})

    if(!user ){
        return res.status(404).json({msg : 'Usuário não encontrado'})
    }

    //verificar se a senha conincide 
    const checkPassord = await bcrypt.compare(password, user.password)
    if(!checkPassord){
        return res.status(422).json({msg : 'Senha incorreta'})
    }

    try{
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        
        )
        res.status(200).json({msg: 'Autenticação realizada com sucesso', token})
    }catch(error){
        console.log(error)
        res.status(500).json({msg: 'Aconteceu algum erro no servidor!'})
    }


})

const dbUser = process.env.DB_USER
const dbPassword = process.env.BR_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.nskqgcr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
.then(()=>{
    app.listen(3000)
    console.log('conectou ao banco!')
})
.catch((err)=>{
    console.log('não conectou ao banco!', err)
})



