const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.port || 5000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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
                    const query = [
                        { 'userName': userName },
                        { 'email': email }];
                    const existUser = await userAuthCollection.findOne({
                        $and: query
                    });
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
                console.log(emailRegexp.test(email), regUser.test(userName), regPass.test(password));
                const result = {
                    acknowledged: false,
                    email: emailRegexp.test(email) ? emailRegexp.test(email): "email have must be @ sign!",
                    userName: regUser.test(userName)? regUser.test(userName):"username must be min 6 character and one letter and one number and '_/.' sign!",
                    password: regPass.test(password) ? regPass.test(password):"Password must be 8 characters with one special character and one letter and one number!"
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
                    else {
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
                    userName: regUser.test(userName) ? regUser.test(userName):"username must be min 6 character and one letter and one number and '_/.' sign!",
                    password: regPass.test(password) ? regPass.test(password):"Password must be 8 characters with one special character and one letter and one number!"
                }
                res.send({ status: false, result });
            }

        })

        app.post('/forgot-password', async (req, res) => {
            const email = req.body.email;
            const query = { email };
            const user = await userAuthCollection.findOne(query);

            if (user) {
                const secret = JWT_SECRET + user.password;
                const payload = {
                    email: user.email,
                    id: user._id
                }
                const token = jwt.sign(payload, secret, { expiresIn: '1d' });
                const link = `https://backend-auth-seven.vercel.app/reset-password?id=${user._id}&token=${token}`;
                console.log(link);

                var transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.USER_EMAIL,
                        pass: process.env.USER_PASSWORD
                    }
                });

                var mailOptions = {
                    from: process.env.USER_EMAIL,
                    to: user.email,
                    subject: 'Reset Password Link within 24 hours',
                    text: link
                };

                transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        res.status(500).send({ msg: err.message });
                    } else {
                        res.status(200).send({ status: true, email: 'Email sent: ' + info.response })
                    }
                });
            }
            else {
                const result = {
                    acknowledged: false,
                    user: "User not exist"
                }
                res.send({ status: false, result });
            }
        })

        app.put('/reset-password', async (req, res) => {
            const { id, token } = req.query;
            const password = req.body.password;
            const query = { _id: new ObjectId(id) };
            const user = await userAuthCollection.findOne(query);

            if (user) {
                const secret = JWT_SECRET + user.password;
                try {
                    const payload = jwt.verify(token, secret);

                    const regPass = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/

                    if (regPass.test(password)) {
                        const encryptedPassword = await bcrypt.hash(password, 10);
                        const { id } = payload;
                        console.log(payload);
                        const filter = { _id: new ObjectId(id) };
                        const options = { upsert: true };
                        const updatedPassword = {
                            $set: {
                                password: encryptedPassword
                            }
                        }
                        const result = await userAuthCollection.updateOne(filter, updatedPassword, options);
                        res.send({ status: true, result });
                    }
                    else {
                        const result = {
                            acknowledged: false,
                            password: regPass.test(password) ? regPass.test(password):"Password must be 8 characters with one special character and one letter and one number."
                        }
                        res.send({ status: false, result });
                    }

                } catch (error) {
                    console.log(error);
                    res.send({ status: false, error });
                }
            }
            else {
                const result = {
                    acknowledged: false,
                    user: "Invalid User"
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