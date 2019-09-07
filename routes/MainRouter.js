var createError = require('http-errors');
const { catchAsync } = require('utils');
const fetch = require('node-fetch');
var express = require('express');
var router = express.Router();
/**********************************ENCRYPTION****************************************/
// Nodejs encryption with CTR
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';

function encrypt(text, key, iv) {
 let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
 let encrypted = cipher.update(text);
 encrypted = Buffer.concat([encrypted, cipher.final()]);
 return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decrypt(text, key, iv) {
 let iv = Buffer.from(text.iv, 'hex');
 let encryptedText = Buffer.from(text.encryptedData, 'hex');
 let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
 let decrypted = decipher.update(encryptedText);
 decrypted = Buffer.concat([decrypted, decipher.final()]);
 return decrypted.toString();
}
/************************************************************************************/



router.get('/',function(req,res){
  res.render('index', {title: 'StormBot', conditins: true, SESSION: req.session})
  console.log(__dirname+'/index.html');
  //__dirname : It will resolve to your project folder.
});




module.exports = router;
