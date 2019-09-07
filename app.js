var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var logger = require('morgan');
const fetch = require('node-fetch');
const btoa = require('btoa');
const { catchAsync } = require('utils');
const hbs = require("express-handlebars");
const config = require('./config.json')


/***********************************MYSQL*DATABASE***********************************/
var mysql = require('mysql');
var con = mysql.createConnection({
  host     : config.host,
  user     : config.user,
  password : config.password,
  database : config.database
});
 
con.connect(function(err) {
  if (err) {
    console.error('error connecting: ' + err.stack);
    console.log("Connection to database could not be established")
    process.exit(1);
    return;
  }
 
  console.log('Database connected as threadID: ' + con.threadId);
});

/************************************************************************************/

/**********************************ENCRYPTION****************************************/
// Nodejs encryption with CTR
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(text) {
 let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
 let encrypted = cipher.update(text);
 encrypted = Buffer.concat([encrypted, cipher.final()]);
 return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decrypt(text) {
 let iv = Buffer.from(text.iv, 'hex');
 let encryptedText = Buffer.from(text.encryptedData, 'hex');
 let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
 let decrypted = decipher.update(encryptedText);
 decrypted = Buffer.concat([decrypted, decipher.final()]);
 return decrypted.toString();
}
/************************************************************************************/

/***********************************DISCORD*BOT**************************************/
const Discord = require('discord.js');
const client = new Discord.Client();
const prefix = "t?";

const activities_list = [
  "?help | V4.1.0", 
  "DEV: ZombieEar#0493"
  ];

client.on('ready', () => {
  console.log(`Logged in as ${client.user.tag}!`);
  setInterval(() => {
    const index = Math.floor(Math.random() * (activities_list.length - 1) + 1); // generates a random number between 1 and the length of the activities array list (in this case 5).
    client.user.setActivity(activities_list[index]); // sets bot's activities to one of the phrases in the arraylist.
  }, 10000);
});
   
client.on('message', message => {
  if (message.content.startsWith(prefix + "test")) {
    const guild = client.guilds.get(message.guild.id);
    var Members = guild.fetchmembers;
    console.log(Members);
    
    guild.members.forEach(member => {
      var userroles = [];
      member.roles.forEach(role => 
        userroles.push({RoleID: role.id, RoleName: role.name, RoleColour: role.hexColor})
      );
      console.log("INSERT: " + member.id + ", " + member.user.username + ", " + member.nickname + ", " + message.guild.id + ", " + JSON.stringify(userroles));
      con.query(`INSERT INTO discordusers VALUES (?, ?, ?, ?, ?, ?, ?, ?) `,
       [member.id, member.user.username, member.user.discriminator, member.nickname, JSON.stringify(userroles), member.user.avatar, message.guild.id, member.joinedAt])
    });
  }
});

client.on("guildCreate", guild => {
  console.log("Joined a new guild: " + guild.name);
  con.query(`INSERT INTO discordguilds (GuildID, GuildName) VALUES(?, ?)`, [guild.id, guild.name]);
})

client.on("guildDelete", guild => {
  console.log("Left guild: " + guild.name);
  con.query(`DELETE FROM discordguilds where GuildID=(?)`, [guild.id]);
})


client.login(config.token);
module.exports.client = client;
/************************************************************************************/

/********************************DISCORD*OAUTH2**************************************/
const CLIENT_ID = config.client_id;
const CLIENT_SECRET = config.client_secret;
const redirect = encodeURIComponent('http://localhost:3000/login/callback');

const app_icon = "https://cdn.discordapp.com/avatars/419272087132307467/8f29b2d01348ca8413a371f22f4a51b3.png";
/************************************************************************************/
var mainRouter = require('./routes/MainRouter');

var app = express();

// view engine setup
app.engine('hbs', hbs({
  extname: 'hbs', 
  defaultLayout: 'layout', 
  layoutsDir: __dirname + '/views/layouts', 
  partialsDir: __dirname + '/views/partials', 
  helpers: {
    StormBot_Icon_URL: app_icon,
    if_equals: function (var1, var2) { 
      if(var1 == var2){
        return true;
      }
      return false; 
    },
    member_records: function (index) { 
      if(index == 5 || index == 10 || index == 15 || index == 20){
        return "</div><div class='w-100 d-flex flex-row'>";
      }
      return ""; 
    }
  }
}));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(session({ 
  /*genid: function(req) {
    return genuuid() // use UUIDs for session IDs
  }, */
  secret: config.secret,
  saveUninitialized: false,
  resave: true,
  rolling: true,
  cookie: { expires: 1800000 } //Expire after 30 minutes - 1800000 milliseconds
}))

const asyncMiddleware = fn =>
  (req, res, next) => {
    Promise.resolve(fn(req, res, next))
      .catch(next);
  };

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

mainRouter.get('/users', function(req, res, next) {
  res.send('' + client.guilds.size);
});

mainRouter.get('/logout', (req, res) => {
  req.session.destroy(function(err) {
  })
  res.redirect("/");
});

mainRouter.get('/login', (req, res, next) => {
  res.redirect(`https://discordapp.com/api/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&scope=identify%20guilds&redirect_uri=${redirect}`);
});

mainRouter.get('/login/callback', async (req, res) => {
  if (!req.query.code) throw new Error('NoCodeProvided');
  const code = req.query.code;
  const creds = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);
  const response = await fetch(`https://discordapp.com/api/oauth2/token?grant_type=authorization_code&code=${code}&redirect_uri=${redirect}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${creds}`,
      },
    });
  const json = await response.json();
  
  const fetchDiscordUserInfo = await fetch('http://discordapp.com/api/users/@me', {
    headers: {
      Authorization: `Bearer ${json.access_token}`,
    }
  });
  const userInfo = await fetchDiscordUserInfo.json();
  req.session.TOKEN = json.access_token;
  req.session.DISCORD_ID = userInfo.id;
  req.session.USER = userInfo.username;
  req.session.DISCRIMINATOR = userInfo.discriminator;
  req.session.AVATAR = userInfo.avatar;
  req.session.AUTH = encrypt(json.access_token);

  res.redirect("/hub");
});

mainRouter.get('/hub', async (req, res, next) => {
  if(req.session.USER){
    const fetchDiscordGuilds = await fetch('http://discordapp.com/api/users/@me/guilds', {
      headers: {
        Authorization: `Bearer ${decrypt(req.session.AUTH)}`,
      }
    });
  const userGuilds = await fetchDiscordGuilds.json();

  var array = [];
  var counter = 0;
  con.query(`SELECT GuildID FROM discordguilds`, (err, dbguilds) => {
    for (var i = 0; i < userGuilds.length; i++ ){
      for (var j = 0; j < dbguilds.length; j++ ){
        if(userGuilds[i].id == dbguilds[j]['GuildID']){
          array[counter] = {id: userGuilds[i].id, name: userGuilds[i].name, icon: userGuilds[i].icon};
          counter++;
        }
      }
    }
    res.render('hub', {conditins: true, SESSION: req.session, GUILDS: array})
  });
  
  }
  else{
    next(createError(401));
  }
});

mainRouter.get('/:GUILDID/dashboard', asyncMiddleware(async (req,res,next) => {
  if(req.session.USER){
    var guild = client.guilds.get(req.params.GUILDID);
    var user = guild.members.get(req.session.DISCORD_ID);

    res.render('dashboard', {title: 'StormBot', conditins: true, SESSION: req.session, DASH: true, id: guild.id, name: guild.name, icon: guild.icon})
  }
  else{
    next(createError(401));
  }
}));

mainRouter.get('/:GUILDID/MemberRecords', asyncMiddleware(async (req,res,next) => {
  if(req.session.USER){
    var guild = client.guilds.get(req.params.GUILDID);
    var array = [];
    con.query(`SELECT * FROM discordusers WHERE ServerID=?`, [req.params.GUILDID], (err, users) => {
      for (var i = 0; i < users.length; i++ ){
        var buffer = new Buffer( users[i]['Roles'] );
        var bufferBase64 = buffer.toString();
        
        var iconurl = "";
        if(users[i]['Icon'] == null){
          iconurl = "../images/temp_discord.png";
        }
        else{
          iconurl = "https://cdn.discordapp.com/avatars/" + users[i]['DiscordID'] + "/" + users[i]['Icon'] + ".png";
        }

        var nick = "";
        if(users[i]['Nickname'] != null){
          nick = "(aka " + users[i]['Nickname'] + ")";
        }

        array[i] = {
          DiscordID: users[i]['DiscordID'], 
          Discriminator: users[i]['Discriminator'], 
          DiscordName: users[i]['UserName'], 
          Nickname: nick, 
          IconUrl: iconurl,
          Roles: JSON.parse(bufferBase64)
        };
      }
      res.render('MemberRecords', {conditins: true, SESSION: req.session, DASH: true, id: req.params.GUILDID, name: guild.name, icon: guild.icon, MEMBERS: array})
    });
  }
  else{
    next(createError(401));
  }
}));

mainRouter.get('/:GUILDID/MemberRecords/:DISCORDID/', asyncMiddleware(async (req,res,next) => {
  if(req.session.USER){
    var guild = client.guilds.get(req.params.GUILDID);
    var array;
    con.query(`SELECT * FROM discordusers WHERE ServerID=? AND DiscordID=?`, [req.params.GUILDID, req.params.DISCORDID], (err, users) => {
        var buffer = new Buffer( users[0]['Roles'] );
        var bufferBase64 = buffer.toString();
        
        var iconurl = "";
        if(users[0]['Icon'] == null){
          iconurl = "../images/temp_discord.png";
        }
        else{
          iconurl = "https://cdn.discordapp.com/avatars/" + users[0]['DiscordID'] + "/" + users[0]['Icon'] + ".png";
        }

        var nick = "";
        if(users[0]['Nickname'] != null){
          nick = "(aka " + users[0]['Nickname'] + ")";
        }

        var array = {
          DiscordID: users[0]['DiscordID'], 
          Discriminator: users[0]['Discriminator'], 
          DiscordName: users[0]['UserName'], 
          Nickname: nick, 
          IconUrl: iconurl,
          Roles: JSON.parse(bufferBase64)
      }
      res.render('Member', {conditins: true, SESSION: req.session, DASH: true, id: req.params.GUILDID, name: guild.name, icon: guild.icon, MEMBERS: array})
    });
  }
  else{
    next(createError(401));
  }
}));

app.use('/', mainRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error', {ERROR: err, SESSION: req.session});
});

module.exports = app;

