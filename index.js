const express = require('express');
const cors = require('cors');
const fileUpload = require('express-fileupload');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = process.env.port || 5000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");

const app = express();

app.use(cors());
app.use(express.json());
app.use(fileUpload());
app.use(express.urlencoded({ extended: false }));

const JWT_SECRET = process.env.ACCESS_TOKEN;

const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.cwbwt8c.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });
console.log(uri);

async function run() {
    try {
        const userAuthCollection = client.db('banano_auth').collection('user_auth');
        const socialMedia = client.db('banano_auth').collection('social_media');

        // authentication and authorization
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
                    email: emailRegexp.test(email) ? emailRegexp.test(email) : "email have must be @ sign!",
                    userName: regUser.test(userName) ? regUser.test(userName) : "username must be min 6 character and one letter and one number and '_/.' sign!",
                    password: regPass.test(password) ? regPass.test(password) : "Password must be 8 characters with one special character and one letter and one number!"
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
                    userName: regUser.test(userName) ? regUser.test(userName) : "username must be min 6 character and one letter and one number and '_/.' sign!",
                    password: regPass.test(password) ? regPass.test(password) : "Password must be 8 characters with one special character and one letter and one number!"
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
                            password: regPass.test(password) ? regPass.test(password) : "Password must be 8 characters with one special character and one letter and one number."
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

        // CRUD operation for social media
        // can view all data without login
        app.get('/social-media/all', async (req, res) => {
            const query = {};
            try {
                const posts = await socialMedia.find(query).toArray();
                res.send(posts);
            } catch (error) {
                res.send({ status: false, error });
            }
        })

        // for logged in user
        app.get('/social-media', async (req, res) => {
            const token = req.headers.authorization;
            if (!token) {
                return res.send({ status: false, error: 'unauthorized access' });
            }
            try {
                const verifiedUser = jwt.verify(token, JWT_SECRET);
                const userName = verifiedUser.userName;
                const posts = await socialMedia.find({ userName }).toArray();
                res.send(posts);
            } catch (error) {
                res.send({ status: false, error });
            }

        })

        app.get('/social-media/:id', async (req, res) => {
            const token = req.headers.authorization;
            if (!token) {
                return res.send({ status: false, error: 'unauthorized access' });
            }
            try {
                const verifiedUser = jwt.verify(token, JWT_SECRET);
                const userName = verifiedUser.userName;
                const id = req.params.id;
                const query = { _id: new ObjectId(id), userName };
                const posts = await socialMedia.find(query).toArray();
                res.send(posts);
            } catch (error) {
                res.send({ status: false, error });
            }

        })

        app.post('/social-media', async (req, res) => {
            const token = req.headers.authorization;
            if (!token) {
                return res.send({ status: false, error: 'unauthorized access' });
            }
            try {
                const verifiedUser = jwt.verify(token, JWT_SECRET);
                const validExtension = ['image/jpeg', 'image/png', 'image/gif', 'image/jpg'];
                const imageExtract = req.files.image.mimetype;
                const validImageExtension = validExtension.includes(imageExtract.toLowerCase());
                if (!validImageExtension) {
                    return res.send({ status: false, result: "Only image can be upload!" })
                }
                const userName = verifiedUser.userName;
                const imageData = req.files.image.data;
                const imageToString = imageData.toString('base64');
                const imageBuffer = Buffer.from(imageToString, 'base64');
                const user = await userAuthCollection.findOne({ userName });
                console.log(imageBuffer);

                if (user) {
                    const socialData = {
                        userName,
                        description: req.body.description,
                        image: imageBuffer
                    }
                    console.log(socialData);
                    try {
                        const result = await socialMedia.insertOne(socialData);
                        res.send(result);
                    } catch (error) {
                        const result = {
                            acknowledged: false,
                            message: "DB error",
                        }
                        res.send({ status: false, result, error });
                    }
                }
                else {
                    const result = {
                        acknowledged: false,
                        message: "user not exist"
                    }
                    res.send({ status: false, result })
                }
            } catch (error) {
                console.log(error);
                const result = {
                    acknowledged: false,
                    message: req.files?.fileName ? "Invalid Token" : "image required"
                }
                res.send({ status: false, result, error });
            }
        })

        app.put('/social-media/:id', async (req, res) => {
            const token = req.headers.authorization;
            if (!token) {
                return res.send({ status: false, error: 'unauthorized access' });
            }
            try {
                const verifiedUser = jwt.verify(token, JWT_SECRET);
                const id = req.params.id;
                const query = { _id: new ObjectId(id), userName: verifiedUser.userName };
                const hasImage = req.files ? true : false;
                const hasDescription = req.body.description ? true : false;
                let updateField = {};

                if (!hasImage && !hasDescription) {
                    return res.send({ status: false, result: "No Input Found" })
                }
                if (hasImage) {
                    const validExtension = ['image/jpeg', 'image/png', 'image/gif', 'image/jpg'];
                    const imageExtract = req.files.image.mimetype;
                    const validImageExtension = validExtension.includes(imageExtract.toLowerCase());
                    if (!validImageExtension) {
                        return res.send({ status: false, result: "Only image can be upload!" })
                    }
                    const imageData = req.files.image.data;
                    const imageToString = imageData.toString('base64');
                    const imageBuffer = Buffer.from(imageToString, 'base64');
                    updateField.image = imageBuffer;
                }
                if (hasDescription) {
                    updateField.description = req.body.description;
                }

                const updatePost = {
                    $set: updateField
                };

                try {
                    const result = await socialMedia.updateOne(query, updatePost);
                    res.send(result);
                } catch (error) {
                    res.send({ status: false, result: "DB error", error });
                }
            } catch (error) {
                res.send({ status: false, message: "token error", error });
            }
        })

        app.delete('/social-media/:id', async (req, res) => {
            const token = req.headers.authorization;
            if (!token) {
                return res.send({ status: false, error: 'unauthorized access' });
            }
            try {
                const verifiedUser = jwt.verify(token, JWT_SECRET);
                const id = req.params.id;
                const userName = verifiedUser.userName;
                try {
                    const posts = await socialMedia.deleteOne({ _id: new ObjectId(id), userName });
                    res.send(posts);
                } catch (error) {
                    res.send({ status: false, result: "DB error", error });
                }
            } catch (error) {
                res.send({ status: false, error });
            }
        })

        // social media like and comment with post api
        // can like and comment without logged in
        app.post('/social-media/like_comment/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const post = await socialMedia.findOne(query);
            if (post) {
                const like = req.body.like;
                const comment = req.body.comment;
                let updateField = {};

                if (!comment && !like) {
                    console.log("enter");
                    return res.send({ status: false, result: "No Input Found!" })
                }
                if (comment) {
                    updateField.comment = comment;
                }
                if (like && ["yes", "no"].includes(like.toLowerCase())) {
                    const postLike = post.like ? parseInt(post.like) : 0;
                    updateField.like = like.toLowerCase() === "yes" ? (postLike + 1) : postLike;
                }
                else if (like && !["yes", "no"].includes(like.toLowerCase())) {
                    console.log("else");
                    return res.send({ status: false, result: "Invalid Like Input" })
                }
                console.log(updateField);

                try {
                    const updatePost = {
                        $set: updateField
                    }
                    console.log(updatePost);
                    const result = await socialMedia.updateOne(query, updatePost);
                    res.send(result);

                } catch (error) {
                    res.send({ status: false, result: "DB Error", error });
                }
            } else {
                res.send({ status: false, result: "No post Found" })
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