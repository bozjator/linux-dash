var express = require('express')
var app     = require('express')()
var server  = require('http').Server(app)
var path    = require('path')
var spawn   = require('child_process').spawn
var fs      = require('fs')
var ws      = require('websocket').server
var args    = require('yargs').argv
var bcrypt  = require("bcryptjs")
var cookieParser = require('cookie-parser')
var port    = args.port || process.env.LINUX_DASH_SERVER_PORT || 80

const authCookieExpiresInDays = 7;
var authTokens = new Array();
var passwordHash;

var authMiddleware = function(req, res, next) {
  const cookies = req.cookies;

  if (req.path.indexOf("/login") === 0) {
    next();
    return;
  }

  if (!cookies || !cookies.authToken) {
    res.sendStatus(401).end();
    return;
  }

  const matchToken = authTokens.find(token => token.token === cookies.authToken);

  if (matchToken !== undefined) {
    next();
  } else {
    res.sendStatus(401).end();
  }
}

app.use(cookieParser());
app.use(express.urlencoded({extended:true}));
app.use(authMiddleware);
app.use(express.static(path.resolve(__dirname + '/../')))

function readPasswordFromFile() {
  const passFilePath = "auth/password.txt";
  try {
    if (fs.existsSync(passFilePath)) {
      fs.readFile(passFilePath, "utf8", function(err, data) {
        passwordHash = data;
      });
    } else {
      console.log("There is not file with password! Use auth/pass-generator.js to generate file with password.");
      process.exit(1);
    }
  } catch(err) {
    console.error(err);
    process.exit(1);
  }
}
readPasswordFromFile();

server.listen(port, function() {
  console.log('Linux Dash Server Started on port ' + port + '!');
})

function checkAuthTokens() {
  const currentDateTime = (new Date()).toUTCString();
  authTokens = authTokens.filter(tokenObject => tokenObject.expires >= currentDateTime);
}
setInterval(checkAuthTokens, 60 * 1000);

app.get('/login', function (req, res) {
	res.sendFile(path.resolve(__dirname + '/../login.html'))
})

app.post('/login', function (req, res) {
  const userPassword = req.body.password;

  // Check if password from user maches with the password saved on server.
  const secretKeyMatches = bcrypt.compareSync(
    userPassword,
    passwordHash
  );

  if (!secretKeyMatches) {
    res.status(401).end();
    return;
  }

  const token = bcrypt.hashSync(new Date().toString(), 10);
  var expires = new Date();
  expires.setTime(expires.getTime() + (authCookieExpiresInDays*24*60*60*1000));
  expires = expires.toUTCString()

  authTokens.push({ token, expires });
  res.status(200).send({ token, expires });
})

app.get('/websocket', function (req, res) {

  res.send({
    websocket_support: true,
  })

})

wsServer = new ws({
	httpServer: server
})

var nixJsonAPIScript = __dirname + '/linux_json_api.sh'

function getPluginData(pluginName, callback) {
  var command = spawn(nixJsonAPIScript, [ pluginName, '' ])
  var output  = []

  command.stdout.on('data', function(chunk) {
    output.push(chunk.toString())
  })

  command.on('close', function (code) {
    callback(code, output)
  })
}

wsServer.on('request', function(request) {
  
	var wsClient = request.accept('', request.origin)

  wsClient.on('message', function(wsReq) {

    var moduleName = wsReq.utf8Data
    var sendDataToClient = function(code, output) {
      if (code === 0) {
        var wsResponse = '{ "moduleName": "' + moduleName + '", "output": "'+ output.join('') +'" }'
        wsClient.sendUTF(wsResponse)
      }
    }

    getPluginData(moduleName, sendDataToClient)

  })

})

app.get('/server/', function (req, res) {

	var respondWithData = function(code, output) {
		if (code === 0) res.send(output.toString())
		else res.sendStatus(500)
	}

  getPluginData(req.query.module, respondWithData)
})
