// authRoutes.js
// ========
module.exports = function (apiUsers, Boom, bcrypt, jwt, secretKey, sendgrid, randomInt) {
	return {
		authenticate: function (request, reply) {
			// Check db for submitted email address in login form
			apiUsers.get(request.payload.email, function (err, result) {
				if (err) {
					// Email address not found
					console.log("ERROR: " + err);
					var error = Boom.unauthorized('Wrong Email or password');
					reply(error);
				}
				else {
					console.log(result);
					// Hash submitted password and compare to db value
					bcrypt.compare(request.payload.password, result.value.password, function (err, res) {
						console.log(res);
						// Is the password correct?
						if (res == true) {
							// Has user confirmed their account?
							if (result.value.accountStatus === 'unverified') {
								reply(Boom.unauthorized('Check your email for account verification'));
							}
							// Generate auth token and user account object
							var authToken = jwt.sign(
								{ email: request.payload.email },
								secretKey
								);

							var user = {};
							user.email = request.payload.email;
							user.firstName = result.value.firstName;
							user.lastName = result.value.lastName;
							// Send auth token and user data to client
							reply({ token: authToken, user: user });
						}
						else {
							// Password doesn't match
							var error = Boom.unauthorized('Wrong email or password');
							reply(error);
						}
					});

				}
			});
		},
		
		forgotPassword: function (request, reply) {
			// Check db for submitted email in reset form
			apiUsers.get(request.payload.email, function(err, result) {
				if (err) {
					// Email not found
					console.log(err);
					reply(err);
				}
				else {
					var user = result.value;
					console.log(user);
					// Generate temporary password
					user.tempPassword = randomInt(1000000, 10000000);
					// Store temp password in db
					apiUsers.replace(request.payload.email, user, function(err, res) {
						if (err) {
							console.log(err);
							reply(err);
						}
						else {
							console.log(res);
							// Generate temp login token
							var tempToken = jwt.sign(
								{ email: request.payload.email, tempPassword: user.tempPassword },
								secretKey
							);
							// Prepare email for temp password
							var email = new sendgrid.Email({
								to: request.payload.email,
								from: 'passwordreset@pedlar.com.au',
								subject: user.firstName + ', your password has been reset.',
								text: 'http://192.168.1.10:9000/#/common/forgot/' + tempToken
							});
							// Send password reset email
							sendgrid.send(email, function (err, res) {
								if (err) { console.log(err); }
								else {
									console.log(res);
									reply({message: 'Password Reset email sent'});
								}
							});
						}
					});
				}
			});
		},
		
		forgotPasswordVerify: function (request, reply) {
			console.log(request.params.resetToken);
			var decodedToken = jwt.decode(request.params.resetToken);
			console.log(decodedToken);
			// Check db for email address from token
			apiUsers.get(decodedToken.email, function (err, result) {
				if (err) {
					console.log(err);
					reply(Boom.unauthorized('Email address not found')); 
				}
				else {
					// Does temp password from token match db temp password?
					var user = result.value;
					if (decodedToken.tempPassword === user.tempPassword) {
						user.tempPassword = null;
						apiUsers.replace(decodedToken.email, user, function(err, res) {
							if (err) {
								console.log(err);
							}
							else {
								console.log(res);
							}
						});
						var userData = {};
						userData.email = user.email;
						userData.firstName = user.firstName;
						userData.lastName = user.lastName;
						var authToken = jwt.sign( { email: user.email}, secretKey);
						reply( { token: authToken, user: userData } );
					}
					else { reply(Boom.unauthorized('Temporary password doesn\'t match')); }
				}
			});
		},

		register: function (request, reply) {
			// Check for existing email address. Succeed if not found
			apiUsers.get(request.payload.email, function (err, result) {
				if (err) {
					// No email account found. OK to proceed
					console.log(err);
					if (err.code == 13) {
						// Generate a salt
						bcrypt.genSalt(10, function (err, salt) {
							if (err) { console.log(err); }
							else {
								// Hash submitted password
								bcrypt.hash(request.payload.password, salt, null, function (err, hash) {
									if (err) { console.log(err); }
									else {
										// Generate registration code
										var regCode = randomInt(1000, 9000);
										// Encrypt regCode and email address
										var regToken = jwt.sign(
											{ email: request.payload.email, registrationCode: regCode },
											secretKey
											);
										// Save user account to db
										apiUsers.insert(request.payload.email, {
											firstName: request.payload.firstName,
											lastName: request.payload.lastName,
											password: hash,
											type: 'userAccount',
											accountStatus: 'unverified',
											registrationCode: regCode
										}, function (err, res) {
												if (err) { reply(err); }
												else {
													// Prepare registration email
													var email = new sendgrid.Email({
														to: request.payload.email,
														from: 'accounts@pedlar.com.au',
														subject: request.payload.firstName + ', please confirm your account.',
														text: 'http://192.168.1.10:9000/#/common/verify/' + regToken
													});
													// Send registration email
													sendgrid.send(email, function (err, res) {
														if (err) { console.log(err); }
														else {
															console.log(res);
															reply({ message: 'email sent' });
														}
													});
												}
											});
									}
								});
							}
						});
					}
				}
				else {
					var error = Boom.conflict('Problem registering. Try a different email address.');
					reply(error);
				}
			});
		},

		registerToken: function (request, reply) {
			// Decode submitted token
			var decodedToken = jwt.decode(request.params.regToken);
			console.log(decodedToken);
			// Attempt to get user account from db using token
			apiUsers.get(decodedToken.email, function (err, result) {
				if (err) { console.log(err); reply(err); }
				else {
					console.log(result.value);
					// Compare submitted regCode with regCode from db
					if (result.value.registrationCode === decodedToken.registrationCode) {
						// Registration code matches database
						var user = result.value;
						user.registrationCode = null;
						user.accountStatus = 'verified';
						// Update user account in db to verified
						apiUsers.replace(decodedToken.email, user, function (err, res) {
							if (err) { console.log(err); reply(err); }
							else {
								// Prepare auth token and send it to client
								var authToken = jwt.sign({ email: user.email }, secretKey);
								var userData = {};
								userData.email = decodedToken.email;
								userData.firstName = user.firstName;
								userData.lastName = user.lastName;

								reply({ token: authToken, user: userData });
							}
						});
					}
					else {
						reply(Boom.unauthorized('Registration code doesn\'t match.'));
					}
				}
			});
		}
	};
};