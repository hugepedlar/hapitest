var Hapi = require('hapi');
var jwt = require('jsonwebtoken');
var couchbase = require('couchbase');

var cluster = new couchbase.Cluster('couchbase://127.0.0.1');
var bucket = cluster.openBucket('apiUsers', 'apiPass');
var ViewQuery = couchbase.ViewQuery;

var query = ViewQuery.from('user_accounts', 'list_users');//.key('david@hedger.com.au');
bucket.query(query, function(err, results) {
	if (err) { console.log(err);}
	else {
		for (i in results) {
			console.log(results[i]);
		}
	}
})

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
		var authQuery = ViewQuery.from('user_accounts', 'list_users').key(request.payload.email);
		bucket.query(authQuery, function (err, results) {
			if (err) { console.log (err)}
			else {
				console.log(results[0]);
				if (results[0].value === request.payload.password) {
					success = true;
					var authToken = jwt.sign (
						{email: results[0].key},
						secretKey
						);
					reply({token: authToken});
				}
				else{
					var error = Hapi.error.unauthorized('Wrong email or password');
					reply(error);
				}
			}
		})
	}
});

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