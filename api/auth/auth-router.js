const router = require('express').Router();
const db = require('../../data/dbConfig')
const bcrypt = require('bcrypt')
const { checkFormat, checkNameTaken,} = require('./auth-middleware')
const JWT = require('jsonwebtoken')
const { JWT_SECRET,BCRYPT_ROUNDS } = require('../../config')

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username
  }
  const options = {
    expiresIn: '1d'
  };
  return JWT.sign(payload,JWT_SECRET,options)
}

router.post('/register', checkFormat, checkNameTaken, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const newUser = {
      username: username,
      password: await bcrypt.hash(password, BCRYPT_ROUNDS)
    };
    const newID = await db('users').insert(newUser);
    const [result] = await db('users').where('id',newID);

    res.status(201).json(result);
  } catch (err) {
    next(err)
  }
});

router.post('/login', checkFormat, async (req, res, next) => {
  try {
    const { username, password } = req.body;

    db('users').where('username', username).first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          const token = generateToken(user);
          res.status(200).json({
            message: `welcome, ${username}`,
            token: token
          });
        }else{
          next({ status: 401, message: 'invalid credentials'});
        }
      })
  } catch (err) {
    next(err)
  }
});

module.exports = router;
