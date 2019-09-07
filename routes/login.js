var express = require('express');
var router = express.Router();

const CLIENT_ID = '613858617073860627';
const CLIENT_SECRET = 'ro7tCcPEVj09rry78dDA_fbzh-ULWdAw';
const redirect = encodeURIComponent('http://localhost:3000/login/callback');

/* GET users listing. */
router.get('/login', (req, res) => {
  res.redirect(`https://discordapp.com/api/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&scope=identify%20guilds&redirect_uri=${redirect}`);
});

router.get('/login/callback/', (req, res) => {
  //res.send('' + req.param("code"));
  var AuthorizationCode = req.param("code");
  res.redirect(`https://discordapp.com/api/oauth2/token?client_id=${CLIENT_ID}&grant_type=authorization_code&code=${AuthorizationCode}&redirect_uri=${redirect}&client_secret=${CLIENT_SECRET}`);
});

module.exports = router;
