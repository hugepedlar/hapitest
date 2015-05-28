var Hapi = require('hapi');
var jwt = require('jsonwebtoken');
var couchbase = require('couchbase');
var Boom = require('boom');
var bcrypt = require('bcrypt-nodejs');

//var hash = bcrypt.hashSync("my password", bcrypt.genSaltSync(10));

var cluster = new couchbase.Cluster('couchbase://127.0.0.1');
var apiUsers = cluster.openBucket('apiUsers', 'apiPass');
var ViewQuery = couchbase.ViewQuery;


var secretKey = 'po3xzUXF7pZVLBkkvzec4B99HjMpqxroK9pGWiokO9Ilu2GsMPNpDrKnjtGVWyL';

var validate = function (decoded, request, callback) {
	var authQuery = ViewQuery.from('user_accounts', 'list_users').key(decoded.email);
	apiUsers.query(authQuery, function (err, results) {
		if (err) { 
			console.log(err);
			return callback(null, false); 
		}
		else {
			if (results == null) {
				return callback(null, false);
			}
			else if (results[0] != null && decoded.email != results[0].key) {
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
	config: { auth: false },
	handler: function (request, reply) {
		var success = false;
		apiUsers.get(request.payload.email, function (err, result) {
			if (err) { 
				console.log("ERROR: " + err);
				var error = Boom.unauthorized('Wrong Email or password');
				reply(error);
			}
			else {
				console.log(result);
				bcrypt.compare(request.payload.password, result.value.password, function (err, res) {
					console.log(res);
					if (res == true) {
						success = true;
						var authToken = jwt.sign(
							{ email: request.payload.email },
							secretKey
							);

						var user = {};
						user.email = request.payload.email;
						user.firstName = result.value.firstName;
						user.lastName = result.value.lastName;
						reply({ token: authToken, user: user });
					}
					else {
						var error = Boom.unauthorized('Wrong email or password');
						reply(error);
					}
				});

			}
		});
	}
});

server.route({
    method: 'POST',
    path: '/register',
	config: { auth: false },
    handler: function (request, reply) {
		apiUsers.get(request.payload.email, function (err, result) {
			if (err) {
				console.log(err);
				if (err.code == 13) {
					bcrypt.genSalt(10, function (err, salt) {
						if (err) { console.log(err); }
						else {
							//make hash
							bcrypt.hash(request.payload.password, salt, null, function (err, hash) {
								if (err) { console.log(err); }
								else {
									// Store hash in DB.
									apiUsers.insert(request.payload.email, {
										firstName: request.payload.firstName,
										lastName: request.payload.lastName,
										password: hash,
										type: 'userAccount'
									}, function (err, res) {
											if (err) { reply(err); }
											else {
												var authToken = jwt.sign(
													{ email: request.payload.email },
													secretKey
													);

												var user = {};
												user.email = request.payload.email;
												user.firstName = request.payload.firstName;
												user.lastName = request.payload.lastName;
												reply({ token: authToken, user: user });
											}
										});
								}
							});
						}
					});
				}
			}
			else {
				var error = Boom.unauthorized('Problem registering. Try a different email address.');
				reply(error);
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