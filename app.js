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
var dateFormat = require('dateformat');
var bodyParser = require("body-parser");
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
var APIRouter = express.Router();

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
    },
    member_activity_sort: function (msg, voip, date, channel) { 
      if(channel == "+"){
        return ('<tr class="clickable" data-toggle="collapse" data-target="' + date + '" aria-expanded="false" aria-controls="' + date + '">'
         + '<td>' + msg + '</td>' 
         + '<td>' + voip + '</td>' 
         + '<td>' + date + '</td>' 
         + '<td>' + channel + '</td>' 
         + '</tr>' 
         + '<tr id="' + date + '" class="collapse table-secondary text-dark">');
      }else{
        return (''
         + '<td>' + msg + '</td>' 
         + '<td>' + voip + '</td>' 
         + '<td>' + date + '</td>' 
         + '<td>' + channel + '</td>' 
         + '</tr>');
      } 
    }
  }
}));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

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
app.use(express.static(path.join(__dirname, '/public')));

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

mainRouter.get('/login/callback', async (req, res, next) => {
  try {
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
  }
  catch(error) {
    next(createError(504));
  }
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

        var activity = {};
        con.query(`SELECT * FROM discordactivity WHERE ServerID=? AND DiscordID=? and 
        ActivityDate Between "2019-09-06" AND "2019-09-15" ORDER BY ActivityDate DESC`,
         [req.params.GUILDID, req.params.DISCORDID], (err, DActivity) => {
          /*
          var current_date = ''
          var str_total = ""
          var str_sub = ""
          var msg = 0
          var voip = 0
          for(var x = 0; x<DActivity.length; x++){
            if (current_date == ''){
              current_date = dateFormat(new Date(DActivity[x]['ActivityDate']), "yyyy-mm-dd");
              str_sub+="<tbody id='" + current_date + "' class='collapse table-secondary text-dark'>"
            }
            if(current_date == dateFormat(new Date(DActivity[x]['ActivityDate']), "yyyy-mm-dd")){
              msg+=DActivity[x]['MSG']
              voip+=DActivity[x]['VOIP']
              str_sub+="<tr><td>" + DActivity[x]['MSG'] +"</td><td>" + DActivity[x]['VOIP'] +"</td><td>" + current_date +"</td><td>" + DActivity[x]['ChannelID'] +"</td></tr>"
            }else{
              str_sub+="</tbody>"
              str_total+="<tr class='clickable' data-toggle='collapse' data-target='#" + current_date + "' aria-expanded='false' aria-controls='" + current_date + "'>"
              str_total+="<td>" + msg +"</td><td>" + voip +"</td><td>" + current_date +"</td><td>+</td></tr>"
              current_date = dateFormat(new Date(DActivity[x]['ActivityDate']), "yyyy-mm-dd");
              str_sub+="<tbody id='" + current_date + "' class='collapse table-secondary text-dark'>"
              msg=DActivity[x]['MSG']
              voip=DActivity[x]['VOIP']
              str_sub+="<tr><td>" + DActivity[x]['MSG'] +"</td><td>" + DActivity[x]['VOIP'] +"</td><td>" + current_date +"</td><td>" + DActivity[x]['ChannelID'] +"</td></tr>"
            }
            if((x+1) >= DActivity.length){
              str_sub+="</tbody>"
              str_total+="<tr class='clickable' data-toggle='collapse' data-target='#" + current_date + "' aria-expanded='false' aria-controls='" + current_date + "'>"
              str_total+="<td>" + msg +"</td><td>" + voip +"</td><td>" + current_date +"</td><td>+</td></tr>"
            }
          }
          var table = "<tbody>" + str_total + "" + str_sub + "</tbody>"
          console.log(table)
          */
         var table = ""
         var current_date = ''
         var str_total = ""
         var str_sub = ""
         var msg = 0
         var voip = 0
         for(var x = 0; x<DActivity.length; x++){
           if (current_date == ''){
             current_date = dateFormat(new Date(DActivity[x]['ActivityDate']), "yyyy-mm-dd");
           }
           if(current_date == dateFormat(new Date(DActivity[x]['ActivityDate']), "yyyy-mm-dd")){
             msg+=DActivity[x]['MSG']
             voip+=DActivity[x]['VOIP']
             str_sub+="<tr class='collapse " + current_date + "' data-parent='#accordion'><td>" + DActivity[x]['MSG'] +"</td><td class='hiddenRow'>" + DActivity[x]['VOIP'] +"</td><td class='hiddenRow'>" + current_date +"</td><td class='hiddenRow'>" + DActivity[x]['ChannelID'] +"</td></tr>"
           }else{
             table+="<tr data-toggle='collapse' data-target='." + current_date + "' class='accordion-toggle'>"
             table+="<td>" + msg +"</td><td>" + voip +"</td><td>" + current_date +"</td><td>+</td></tr>"
             table+=str_sub
             str_sub=""
             current_date = dateFormat(new Date(DActivity[x]['ActivityDate']), "yyyy-mm-dd");
             msg=DActivity[x]['MSG']
             voip=DActivity[x]['VOIP']
             str_sub+="<tr class='collapse " + current_date + "' data-parent='#accordion'><td>" + DActivity[x]['MSG'] +"</td><td>" + DActivity[x]['VOIP'] +"</td><td>" + current_date +"</td><td>" + DActivity[x]['ChannelID'] +"</td></tr>"
           }
           if((x+1) >= DActivity.length){
             table+="<tr data-toggle='collapse' data-target='." + current_date + "' class='accordion-toggle'>"
             table+="<td>" + msg +"</td><td>" + voip +"</td><td>" + current_date +"</td><td>+</td></tr>"
             table+=str_sub
             str_sub=""
           }
         }
         var mytable = "<tbody id='accordion'>" + table + "</tbody>"
         console.log(mytable)

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
          res.render('Member', {conditins: true, SESSION: req.session, DASH: true, id: req.params.GUILDID, name: guild.name, icon: guild.icon, MEMBERS: array, Table: mytable})
        });
        
    });
  }
  else{
    next(createError(401));
  }
}));

mainRouter.get('/:GUILDID/automessage', asyncMiddleware(async (req,res,next) => {
  if(req.session.USER){
    var guild = client.guilds.get(req.params.GUILDID);

    con.query(`SELECT * FROM stormbotmessages WHERE ServerID=? ORDER BY LastUpdate DESC`,
         [req.params.GUILDID], (err, SMessages) => {

          var out = ""
          var model = ""
          for(var x = 0; x<SMessages.length; x++){
            out+='<div class="card text-center bg-secondary text-white">'
              out+='<div class="row">'
                out+='<div class="col-md-2">'
                  out+='' + SMessages[x]['Title']
                out+='</div>'
                out+='<div class="col-md-9">'
                  out+='<div class="card text-center bg-secondary text-white">'
                    out+='<div class="card-body">'
                      out+='' + SMessages[x]['Description']
                    out+='</div>'
                    out+='<div class="card-footer">'
                      out+='' + SMessages[x]['Footer']
                    out+='</div>'
                  out+='</div>'
                out+='</div>'
                out+='<div class="col-md-1">'
                  out+='<div class="row-md-2">'
                    out+='<div class="btn-group">'
                      out+='<button type="button" class="btn btn-warning" data-toggle="modal" data-target="#EditMessageModal' + SMessages[x]['ID'] + '">E</button>'
                      out+='<button type="button" class="btn btn-danger" data-toggle="modal" data-target="#RemoveMessageModal' + SMessages[x]['ID'] + '">X</button>'
                    out+='</div>'
                  out+='</div>'
                  out+='<br>'
                  out+='<div class="row-md-2">'
                    if(SMessages[x]['IsActive'] == 1){
                      out+="<input type='checkbox' checked data-toggle='toggle' data-onstyle='success' data-offstyle='danger' onclick=''>"
                    }else{
                      out+="<input type='checkbox' data-toggle='toggle' data-onstyle='success' data-offstyle='danger' onclick=''>"
                    }
                  out+='</div>'
                out+='</div>'
              out+='</div>'
            out+='</div>'
            out+='<br>'

            model+='<div class="modal fade" tabindex="-1" role="dialog" id="RemoveMessageModal' + SMessages[x]['ID'] + '">'
              model+='<form action="/API/DeleteMessage/' + req.params.GUILDID +'/" method="post">'
                model+='<div class="modal-dialog" role="document">'
                  model+='<div class="modal-content">'
                    model+='<div class="modal-header">'
                      model+='<h5 class="modal-title">WARNING</h5>'
                      model+='<button type="button" class="close" data-dismiss="modal" aria-label="Close">'
                        model+='<span aria-hidden="true">&times;</span>'
                      model+='</button>'
                    model+='</div>'
                    model+='<div class="modal-body">'
                      model+='<p>You are about to delete the message titled "' + SMessages[x]['Title'] + '". Are you sure you want to continue?</p>'
                      model+='<input id="ID" name="ID" type="hidden" value="' + SMessages[x]['ID'] + '">'
                    model+='</div>'
                    model+='<div class="modal-footer">'
                      model+='<button type="submit" class="btn btn-danger">Delete</button>'
                      model+='<button type="button" class="btn btn-primary" data-dismiss="modal">Cancel</button>'
                    model+='</div>'
                  model+='</div>'
                model+='</div>'
              model+='</form>'
            model+='</div>'

            model+='<div class="modal fade bd-example-modal-xl" tabindex="-1" role="dialog" id="EditMessageModal' + SMessages[x]['ID'] + '">'
              model+='<form action="/API/UpdateMessage/' + req.params.GUILDID +'/" method="post">'
                model+='<div class="modal-dialog modal-xl" role="document">'
                  model+='<div class="modal-content">'
                    model+='<div class="modal-header">'
                      model+='<h5 class="modal-title">Edit Message</h5>'
                      model+='<button type="button" class="close" data-dismiss="modal" aria-label="Close">'
                        model+='<span aria-hidden="true">&times;</span>'
                      model+='</button>'
                    model+='</div>'
                    model+='<div class="modal-body">'
                      model+='<div class="form-group">'
                        model+='<label for="Title">Title</label>'
                        model+='<input type="text" class="form-control" id="Title" name="Title" aria-describedby="Embed Title" placeholder="Enter Title" value="' + SMessages[x]['Title'] + '">'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="Url">URL</label>'
                        model+='<input type="text" class="form-control" id="Url" name="Url" aria-describedby="Embed URL" placeholder="Enter URL" value="' + SMessages[x]['URL'] + '">'
                        model+='<small id="urlHelp" class="form-text text-muted">Not Required</small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="Thumbnail">Thumbnail</label>'
                        model+='<input type="text" class="form-control" id="Thumbnail" name="Thumbnail" aria-describedby="Embed Thumbnail" placeholder="Enter Thumbnail" value="' + SMessages[x]['Thumbnail'] + '">'
                        model+='<small id="thumbnailHelp" class="form-text text-muted">Not Required. Must be a url link to an image. <a href="https://imggmi.com" target="_blank">Upload</a></small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="Body">Body</label>'
                        model+='<textarea class="form-control" id="Body" name="Body" rows="4">' + SMessages[x]['Description'] + '</textarea>'
                        model+='<small id="bodyHelp" class="form-text text-muted"></small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="Footer">Footer</label>'
                        model+='<input type="text" class="form-control" id="Footer" name="Footer" aria-describedby="Embed Footer" placeholder="Enter Footer" value="' + SMessages[x]['Footer'] + '">'
                        model+='<small id="footerHelp" class="form-text text-muted"></small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="simple-color-picker">Colour</label>'
                        model+='<input id="simple-color-picker" name="Colour" type="text" class="form-control" value="' + SMessages[x]['Colour'] + '">'
                        model+='<small id="simple-color-pickerHelp" class="form-text text-muted"></small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<small class="form-text text-muted"> Last Edited By: ' + SMessages[x]['LastEdited'] + ' on ' + SMessages[x]['LastUpdate'] + '</small>'
                        model+='<input id="ID" name="ID" type="hidden" value="' + SMessages[x]['ID'] + '">'
                      model+='</div>'
                    model+='</div>'
                    model+='<div class="modal-footer">'
                      model+='<button type="submit" class="btn btn-primary">Update</button>'
                      model+='<button type="button" class="btn btn-primary" data-dismiss="modal">Cancel</button>'
                    model+='</div>'
                  model+='</div>'
                model+='</div>'
              model+='</form>'
            model+='</div>'
          }

          model+='<div class="modal fade bd-example-modal-xl" tabindex="-1" role="dialog" id="AddMessageModal">'
              model+='<form action="/API/AddMessage/' + req.params.GUILDID +'/" method="post">'
                model+='<div class="modal-dialog modal-xl" role="document">'
                  model+='<div class="modal-content">'
                    model+='<div class="modal-header">'
                      model+='<h5 class="modal-title">Create Message</h5>'
                      model+='<button type="button" class="close" data-dismiss="modal" aria-label="Close">'
                        model+='<span aria-hidden="true">&times;</span>'
                      model+='</button>'
                    model+='</div>'
                    model+='<div class="modal-body">'
                      model+='<div class="form-group">'
                        model+='<label for="Title">Title</label>'
                        model+='<input type="text" class="form-control" id="Title" name="Title" aria-describedby="Embed Title" placeholder="Enter Title" value="">'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="Url">URL</label>'
                        model+='<input type="text" class="form-control" id="Url" name="Url" aria-describedby="Embed URL" placeholder="Enter URL" value="">'
                        model+='<small id="urlHelp" class="form-text text-muted">Not Required</small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="Thumbnail">Thumbnail</label>'
                        model+='<input type="text" class="form-control" id="Thumbnail" name="Thumbnail" aria-describedby="Embed Thumbnail" placeholder="Enter Thumbnail" value="">'
                        model+='<small id="thumbnailHelp" class="form-text text-muted">Not Required. Must be a url link to an image. <a href="https://imggmi.com" target="_blank">Upload</a></small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="Body">Body</label>'
                        model+='<textarea class="form-control" id="Body" name="Body" rows="4"></textarea>'
                        model+='<small id="bodyHelp" class="form-text text-muted"></small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="Footer">Footer</label>'
                        model+='<input type="text" class="form-control" id="Footer" name="Footer" aria-describedby="Embed Footer" placeholder="Enter Footer" value="">'
                        model+='<small id="footerHelp" class="form-text text-muted"></small>'
                      model+='</div>'
                      model+='<div class="form-group">'
                        model+='<label for="simple-color-picker">Colour</label>'
                        model+='<input id="simple-color-picker" name="Colour" type="text" class="form-control" value="#0099ff">'
                        model+='<small id="simple-color-pickerHelp" class="form-text text-muted"></small>'
                      model+='</div>'
                    model+='</div>'
                    model+='<div class="modal-footer">'
                      model+='<button type="submit" class="btn btn-primary">Add</button>'
                      model+='<button type="button" class="btn btn-primary" data-dismiss="modal">Cancel</button>'
                    model+='</div>'
                  model+='</div>'
                model+='</div>'
              model+='</form>'
            model+='</div>'

        con.query(`SELECT * FROM stormbotmessageschannels WHERE ServerID=?`,
         [req.params.GUILDID], (err, SMChannel) => {

            var Cout = ""
            for(var j = 0; j<SMChannel.length; j++){
              Cout+='<div class="card text-center bg-secondary text-white">'
                Cout+='<div class="row">'
                  Cout+='<div class="col-md-9">'
                    Cout+='' + SMChannel[j]['ChannelID']
                  Cout+='</div>'
                  Cout+='<div class="col-md-1">'
                    Cout+='<div class="row-md-1">'
                      Cout+='<div class="btn-group">'
                        Cout+='<button type="button" class="btn btn-sm btn-danger" data-toggle="modal" data-target="#RemoveChannelModal' + SMChannel[j]['ChannelID'] + '">X</button>'
                      Cout+='</div>'
                    Cout+='</div>'
                    Cout+='<br>'
                  Cout+='</div>'
                Cout+='</div>'
              Cout+='</div>'
              Cout+='<br>'

              model+='<div class="modal fade" tabindex="-1" role="dialog" id="RemoveChannelModal' + SMChannel[j]['ChannelID'] + '">'
              model+='<div class="modal-dialog" role="document">'
                model+='<div class="modal-content">'
                  model+='<div class="modal-header">'
                    model+='<h5 class="modal-title">WARNING</h5>'
                    model+='<button type="button" class="close" data-dismiss="modal" aria-label="Close">'
                      model+='<span aria-hidden="true">&times;</span>'
                    model+='</button>'
                  model+='</div>'
                  model+='<div class="modal-body">'
                    model+='<p>You are about to remove the channel with ID  "' + SMChannel[j]['ChannelID'] + '". Are you sure you want to continue?</p>'
                  model+='</div>'
                  model+='<div class="modal-footer">'
                    model+='<button type="button" class="btn btn-danger">Delete</button>'
                    model+='<button type="button" class="btn btn-primary" data-dismiss="modal">Cancel</button>'
                  model+='</div>'
                model+='</div>'
              model+='</div>'
            model+='</div>'
            }

            
            res.render('automessage', {title: 'StormBot', conditins: true, SESSION: req.session, DASH: true, id: guild.id, name: guild.name, icon: guild.icon, Messages: out, Channels: Cout, Model: model})
        });
    });
  }
  else{
    next(createError(401));
  }
}));

APIRouter.post('/UpdateMessage/:GUILDID/', asyncMiddleware(async (req,res,next) => {
  con.query(`UPDATE stormbotmessages SET Title=?, URL=?, Description=?, Footer=?, Thumbnail=?, Colour=?, LastEdited=?, LastUpdate=CURRENT_TIMESTAMP WHERE ID=?`,
         [req.body.Title, req.body.Url, req.body.Body, req.body.Footer, req.body.Thumbnail, req.body.Colour, req.session.DISCORD_ID, req.body.ID], (err, SMChannel) => {
          res.redirect("/" + req.params.GUILDID + "/automessage");
  });
}));
APIRouter.post('/AddMessage/:GUILDID/', asyncMiddleware(async (req,res,next) => {
  con.query(`INSERT INTO stormbotmessages (Title, URL, Description, Footer, Thumbnail, Colour, IsActive, ServerID, LastUpdate, LastEdited) VALUES (?, ?, ?, ?, ?, ?, 1, ?, CURRENT_TIMESTAMP, ?)`,
         [req.body.Title, req.body.Url, req.body.Body, req.body.Footer, req.body.Thumbnail, req.body.Colour, req.params.GUILDID, req.session.DISCORD_ID], (err, SMChannel) => {
          res.redirect("/" + req.params.GUILDID + "/automessage");
  });
}));
APIRouter.post('/DeleteMessage/:GUILDID/', asyncMiddleware(async (req,res,next) => {
  con.query(`DELETE FROM stormbotmessages WHERE ID=? AND ServerID=?`,
         [req.body.ID, req.params.GUILDID], (err, SMChannel) => {
          res.redirect("/" + req.params.GUILDID + "/automessage");
  });
}));

app.use('/API', APIRouter);
app.use('/', mainRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
const HTTP_SERVER_ERROR = 500;
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  if (res.headersSent) {
    return next(err);
  }

  // render the error page
  res.status(err.status || HTTP_SERVER_ERROR);
  res.render('error', {ERROR: err, SESSION: req.session});
});

module.exports = app;

