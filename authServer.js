require('dotenv').config();
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json());

const users = [];

app.get('/users', (req, res) => {
    res.json(users);
})

app.post('/users', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        const user = { name: req.body.name, password: hashedPassword }
        users.push(user);
        res.status(201).send();
    } catch {
        res.status(500).send();
    }
})

let refreshTokens = [];

app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken })
    })
})

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
})

app.post('/login', async (req, res) => {
    const user = users.find(user => user.name === req.body.username);
    if (user == null) {
        return res.status(400).json("Cannot find user");
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = generateAccessToken(user);
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
            refreshTokens.push(refreshToken);
            res.json({ accessToken: accessToken, refreshToken: refreshToken });
        } else {
            res.send("Not Allowed")
        }
    } catch {
        res.status(500).send();
    }
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
}

app.listen(4000);
