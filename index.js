var Hapi = require('hapi');
var jwt = require('jsonwebtoken');
var couchbase = require('couchbase');
var Boom = require('boom');
var bcrypt = require('bcrypt-nodejs');
var smtpKey = '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';
var sendgrid = require('sendgrid')(smtpKey);
var Joi = require('joi');




var cluster = new couchbase.Cluster('couchbase://127.0.0.1');
var apiUsers = cluster.openBucket('apiUsers', 'apiPass');
var ViewQuery = couchbase.ViewQuery;



var secretKey = 'po3xzUXF7pZVLBkkvzec4B99HjMpqxroK9pGWiokO9Ilu2GsMPNpDrKnjtGVWyL';

function randomInt (low, high) {
    return Math.floor(Math.random() * (high - low) + low);
}

var openRoutes = require('./openRoutes');
var authRoutes = require('./authRoutes')(apiUsers, Boom, bcrypt, jwt, secretKey, sendgrid, randomInt);

var validate = function (decoded, request, callback) {
	
	// Try to retrieve user account record from db based on email field in auth token
	var authQuery = ViewQuery.from('user_accounts', 'list_users').key(decoded.email);
	apiUsers.query(authQuery, function (err, results) {
		if (err) {
			// DB error 
			console.log(err);
			return callback(null, false); 
		}
		else {
			if (results == null) {
				// No results from db
				return callback(null, false);
			}
			else if (results[0] != null && decoded.email != results[0].key) {
				// Results retrieved but no email match
				 return callback(null, false); 
			}
			else {
				// Email account found in database. Success
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

// Add the routes
server.route({
	method: 'POST',
	path: '/authenticate',
	config: { 
		auth: false,
		validate: {
			payload: {
				email: Joi.string().email(),
				password: Joi.string().min(2)
			}
		} 
	},
	handler: authRoutes.authenticate
});

server.route({
	method: 'POST',
	path: '/authenticate/forgot',
	config: { 
		auth: false,
		validate: {
			payload: {
				email: Joi.string().email()
			}
		} 
	},
	handler: authRoutes.forgotPassword
});

server.route({
	method: 'GET',
	path: '/authenticate/forgot/{resetToken}',
	config: { 
		auth: false
	},
	handler: authRoutes.forgotPasswordVerify
});

server.route({
    method: 'POST',
    path: '/register',
	config: { 
		auth: false,
		validate: {
			payload: {
				email: Joi.string().email().required(),
				password: Joi.string().min(2).required(),
				passwordConfirm: Joi.string().min(2),
				firstName: Joi.string().required(),
				lastName: Joi.string().required()
			}
		} 
	},
    handler: authRoutes.register
});

server.route({
    method: 'GET',
    path: '/register/{regToken}',
	config: { auth: false },
    handler: authRoutes.registerToken
});

server.route({
    method: 'GET',
    path:'/hello',
	config: {auth: 'jwt'}, 
    handler: openRoutes.hello
});

// Start the server
server.start();


