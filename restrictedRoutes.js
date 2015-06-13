// restrictedRoutes.js
// ========
module.exports = function (apiUsers, Boom, bcrypt, jwt, sendgrid) {
  return {
    
    changePassword: function (request, reply) {
      console.log(request.payload);
      
      // Check db for email address of user
      apiUsers.get(request.payload.email, function (err, result) {
        if (err) {
          console.log(err);
          reply(Boom.unauthorized('Email address not found'));
        }
        else {
          // Compare submitted oldPassword with password in db
          bcrypt.compare(request.payload.oldPassword, result.value.password, function (err, res) {
            console.log(result.value.password);
            if (res == true) {
              // Passwords match
              var user = result.value;
              bcrypt.genSalt(10, function (err, salt) {
                if (err) { console.log(err); }
                else {
                  // Hash new password
                  bcrypt.hash(request.payload.password, salt, null, function (err, hash) {
                    if (err) { console.log(err); }
                    else {
                      user.password = hash;
                      // Update new password in db
                      apiUsers.replace(request.payload.email, user, function (err, res) {
                        if (err) {
                          console.log(err);
                          reply(err);
                        }
                        else {
                          console.log(res);
                          // Send user data back to client
                          var userData = {};
                          userData.email = user.email;
                          userData.firstName = user.firstName;
                          userData.lastName = user.lastName;
                          reply(userData);
                        }
                      });

                    }
                  });
                }
              });
            }
            else {
              console.log(err);
            }
          });
        }
      });
    } // <-- use a comma here between functions.
  };
};