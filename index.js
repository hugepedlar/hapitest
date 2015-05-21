var Hapi = require('hapi');
var jwt = require('jsonwebtoken');

var secretKey = 'secretkey123';
// Temp test token
var tempToken = jwt.sign({id: 'a1'}, secretKey);
console.log(tempToken);

var validate = function (decoded, request, callback) {
	if (decoded.id != 'a1') {
		return callback(null, false);
	}
	else {
		return callback(null, true);
	}
};

// Create a server with a host and port
var server = new Hapi.Server();
server.connection({ 
    host: 'localhost', 
    port: 8000 
});

// Register plugins
server.register(require('hapi-auth-jwt2'), function (err) {
	
	if (err){
		console.log(err);
	}
	
	server.auth.strategy('jwt', 'jwt', true, {
		key: secretKey,
		validateFunc: validate
	});
});

// Add the route
server.route({
    method: 'GET',
    path:'/hello',
	config: {auth: false}, 
    handler: function (request, reply) {
       reply(tempToken);
    }
});

server.route({
    method: 'GET',
    path:'/restricted',
	config: {auth: 'jwt'}, 
    handler: function (request, reply) {
       reply('authenticated');
    }
});

// Start the server
server.start();