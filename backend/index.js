import express from 'express'
import { collectionName, connection } from './dbconfig.js';
import cors from 'cors'
import { ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

dotenv.config();
const port = process.env.PORT;
const app = express();

app.use(express.json())
app.use(cors({
    origin: 'https://tasks-frontend-hfbl.onrender.com', // frontend URL
    credentials: true
}))
app.use(cookieParser())

// ------------------- SIGN UP -------------------
app.post('/signup', async (req, res) => {
    const userData = req.body;

    if (userData.email && userData.password) {
        const db = await connection()
        const collection = await db.collection('users')
        const result = await collection.insertOne(userData)

        if (result) {
            jwt.sign(userData, 'Google', { expiresIn: '5d' }, (err, token) => {
                if (err) return res.send({ success: false, msg: 'JWT error' });
                // Set cookie
                res.cookie('token', token, {
                    httpOnly: true,
                    secure: true,         // only HTTPS
                    sameSite: 'none',     // cross-site cookie
                    maxAge: 5 * 24 * 60 * 60 * 1000 // 5 days
                })

                res.send({
                    success: true,
                    msg: 'Sign up done'
                })
            })
        } else {
            res.send({ success: false, msg: 'Sign up failed' })
        }
    } else {
        res.send({ success: false, msg: 'Email and password required' })
    }
})

// ------------------- LOGIN -------------------
app.post('/login', async (req, res) => {
    const userData = req.body;

    if (userData.email && userData.password) {
        const db = await connection()
        const collection = await db.collection('users')
        const result = await collection.findOne({ email: userData.email, password: userData.password })

        if (result) {
            jwt.sign(userData, 'Google', { expiresIn: '5d' }, (err, token) => {
                if (err) return res.send({ success: false, msg: 'JWT error' });
                // Set cookie
                res.cookie('token', token, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'none',
                    maxAge: 5 * 24 * 60 * 60 * 1000
                })

                res.send({ success: true, msg: 'User logged in' })
            })
        } else {
            res.send({ success: false, msg: 'User not found' })
        }
    } else {
        res.send({ success: false, msg: 'Email and password required' })
    }
})

// ------------------- MIDDLEWARE -------------------
function verfiyJWTToken(req, res, next) {
    const token = req.cookies['token'];
    if (!token) {
        return res.send({ success: false, msg: "Token not found" });
    }

    jwt.verify(token, 'Google', (err, decoded) => {
        if (err) {
            return res.send({ success: false, msg: "Invalid token" })
        }
        next();
    })
}

// ------------------- TASK ROUTES -------------------
app.post('/add-task', verfiyJWTToken, async (req, res) => {
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.insertOne(req.body);
    if (result) res.send({ message: "New task added", success: true, result });
    else res.send({ message: "Failed", success: false });
})

app.get('/tasks', verfiyJWTToken, async (req, res) => {
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.find().toArray();
    if (result) res.send({ message: "Task list fetched", success: true, result });
    else res.send({ message: "Try after some time", success: false });
})

app.get('/task/:id', verfiyJWTToken, async (req, res) => {
    const id = req.params.id
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.findOne({ _id: new ObjectId(id) })
    if (result) res.send({ message: "Task fetched", success: true, result })
    else res.send({ message: "Try after some time", success: false })
})

app.delete('/delete/:id', verfiyJWTToken, async (req, res) => {
    const id = req.params.id
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.deleteOne({ _id: new ObjectId(id) })
    if (result) res.send({ message: "Task deleted", success: true, result })
    else res.send({ message: "Try after some time", success: false })
})

app.delete('/delete-multiple', verfiyJWTToken, async (req, res) => {
    const ids = req.body;
    const deleteTaskIds = ids.map((id) => new ObjectId(id));
    const db = await connection();
    const collection = await db.collection(collectionName);
    const result = await collection.deleteMany({ _id: { $in: deleteTaskIds } });
    if (result) res.send({ message: "Tasks deleted", success: true })
    else res.send({ message: "Try after some time", success: false })
})

app.put('/update-task', verfiyJWTToken, async (req, res) => {
    const db = await connection();
    const collection = await db.collection(collectionName);
    const { _id, ...fields } = req.body
    const update = { $set: fields }
    const result = await collection.updateOne({ _id: new ObjectId(_id) }, update)
    if (result) res.send({ message: "Task updated", success: true })
    else res.send({ message: "Try after some time", success: false })
})

app.get('/', verfiyJWTToken, (req, res) => {
    res.send({ message: 'Server running', success: true })
})

app.listen(port, () => console.log(`Server is running on ${port}`))
