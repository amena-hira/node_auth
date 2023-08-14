const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.port || 5000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.ACCESS_TOKEN;

const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.cwbwt8c.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });
console.log(uri);

async function run() {
    try {
        const userAuthCollection = client.db('banano_auth').collection('user_auth');
        app.post('/signup', async (req, res) => {
            const userName = req.body.userName;
            const email = req.body.email;
            const password = req.body.password;

            const encryptedPassword = await bcrypt.hash(req.body.password, 10);

            const emailRegexp = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
            const regUser = /^[^\W_](?!.*?[._]{2})[\w.]{4,18}[^\W_]$/;
            const regPass = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/


            if (emailRegexp.test(email) && regUser.test(userName) && regPass.test(password)) {

                const encryptedPassword = await bcrypt.hash(password, 10);
                const user = {
                    userName,
                    email,
                    password: encryptedPassword
                }
                console.log(user);

                try {
                    const existUser = await userAuthCollection.findOne({ userName });
                    if (existUser) {
                        result = {
                            acknowledged: false,
                            user: "exist user"
                        }
                        res.send({ status: false, result });
                    }
                    else {
                        const result = await userAuthCollection.insertOne(user);
                        res.send({ status: true, result });
                    }
                } catch (error) {
                    console.log(error);
                    result = {
                        acknowledged: false,
                        user: "DB error"
                    }
                    res.send({ status: false, result, error });
                }
            }
            else {
                const result = {
                    acknowledged: false,
                    email: emailRegexp.test(email),
                    userName: regUser.test(userName),
                    password: regPass.test(password)
                }
                res.send({ status: false, result });
            }

        })

        app.post('/login', async (req, res) => {
            const user = req.body;
            const userName = req.body.userName;
            const password = req.body.password;

            const regUser = /^[^\W_](?!.*?[._]{2})[\w.]{4,18}[^\W_]$/;
            const regPass = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/

            if (regUser.test(userName) && regPass.test(password)) {
                const query = { userName };
                const result = await userAuthCollection.findOne(query);

                if (result) {
                    const checkPassword = result.password;
                    let validPassword = await bcrypt.compare(password, checkPassword);
                    console.log(validPassword);
                    if (validPassword) {
                        const token = jwt.sign({ userName }, JWT_SECRET, { expiresIn: '1d' })
                        console.log(token);
                        res.send({ status: true, token: token });
                    }
                    else{
                        const result = {
                            acknowledged: false,
                            user: "Password wrong"
                        }
                        res.send({ status: false, result });
                    }
                }
                else {
                    const result = {
                        acknowledged: false,
                        user: "Username wrong"
                    }
                    res.send({ status: false, result });
                }
            }
            else {
                const result = {
                    acknowledged: false,
                    userName: regUser.test(userName),
                    password: regPass.test(password)
                }
                res.send({ status: false, result });
            }

        })
    }
    finally {

    }
}
run().catch(error => console.log(error));

app.get('/', async (req, res) => {
    res.send("server is running");
})

app.listen(port, () => console.log(`server running on ${port}`));