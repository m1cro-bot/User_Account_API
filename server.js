const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const port = 8000;
const privatKey = 'secret'
app.use(express.urlencoded({extended: false}));

//make dumy database
const Users = {
    admin: { //is username
        name: 'admin' //is name
    }
}
bcrypt.hash('admin', 10, (err, result) => {
    Users.admin.password = result
})
//dumy local storage
const localStorage = {
    token: ''
}

const getToken = (userID, fx) => {
    jwt.sign({userID: userID}, privatKey, {expiresIn: 64800}, (err, token) => {
        if(err) return fx(new Error('fail to generate token'))
        localStorage.token = token
        return fx(null)
    })
}

const register = (name, username, password, fx) => {
    //store in dumy database without verified input
    if(Users[username]) throw fx(new Error('Username has already used'))
    bcrypt.hash(password, 10, (err, hash) => {
        //store registered acount to dummy database
        Users[username] = {
            name: name,
            password: hash
        }
        //store token to localStorage
        getToken(username, (err) => {
            if(err) return err
            return fx(null, username)
        })
    })
}

const login = (username, password, fx) => {
    let user = Users[username]
    if(!user) throw fx(new Error('username incorect'))
    bcrypt.compare(password, user.password, (err, result) => {
        if(err) throw fx(new Error('password incorect'))
        getToken(username, (err) => {
            if(err) return err
            return fx(null, user)
        })
    })
}

const logout = () => {
    //remove token in local storage
}

const authorization = (req, res, next) => {
    jwt.verify(localStorage.token, privatKey, (err, result) => {
        if(err) return res.send('you cant access this page, please login or register');
        return next()
    })
}



//login page
app.post('/login', (req, res) => {
    login(req.body.username, req.body.password, (err, user) => {
        if(err) return err
        return  res.redirect('/main');
    })
});

//register page
app.post('/register', (req, res) => {
    register(req.body.name, req.body.username, req.body.password, (err, user) => {
        if(err) return err;
        if(user) {
             res.json('your acount is registered, you can access main page');
        }
    })
});

//privat access page
app.get('/main', authorization, (req, res) => {
        res.send('yea... you can access main page');
});

app.listen(port, () => {
    console.log(`Server started on port`);
});