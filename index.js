var Hapi = require('hapi');
var jwt = require('jsonwebtoken');
var couchbase = require('couchbase');
var Boom = require('boom');

var cluster = new couchbase.Cluster('couchbase://127.0.0.1');
var apiUsers = cluster.openBucket('apiUsers', 'apiPass');
var ViewQuery = couchbase.ViewQuery;


var secretKey = 'secretkey123';

var validate = function (decoded, request, callback) {
	var authQuery = ViewQuery.from('user_accounts', 'list_users').key(decoded.email);
	apiUsers.query(authQuery, function (err, results) {
		if (err) { console.log(err); }
		else {
			if (decoded.email != results[0].key) {
				return callback(null, false);
			}
			else {
				return callback(null, true);
			}
		}
	});
	
};

// Create a server with a host and port
var server = new Hapi.Server();
server.connection({ 
    host: '0.0.0.0', 
    port: 8000,
	routes: {cors: true} 
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
	method: 'POST',
	path: '/authenticate',
	config: {auth: false},
	handler: function (request, reply) {
		var success = false;
		apiUsers.get(request.payload.email, function (err, result) {
			if (err) { console.log ("ERROR: " + err);}
			else {
				console.log(result);
				if (result.value.password === request.payload.password) {
					success = true;
					var authToken = jwt.sign (
						{email: request.payload.email},
						secretKey
						);
					
					var user = {};
					user.email = request.payload.email;
					user.firstName = result.value.firstName;
					user.lastName = result.value.lastName;
					reply({token: authToken, user: user});
				}
				else{
					var error = Boom.unauthorized('Wrong email or password');
					reply(error);
				}
			}
		});
	}
});

server.route({
    method: 'GET',
    path:'/hello',
	config: {auth: false}, 
    handler: function (request, reply) {
       reply('hi');
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