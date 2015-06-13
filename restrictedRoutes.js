// restrictedRoutes.js
// ========
module.exports = function (apiUsers, Boom, bcrypt, jwt, sendgrid) {
  return {
    
    changePassword: function (request, reply) {
      console.log(request.payload);
      apiUsers.get(request.payload.email, function (err, result) {
        if (err) {
          console.log(err);
          reply(Boom.unauthorized('Email address not found'));
        }
        else {
          bcrypt.compare(request.payload.oldPassword, result.value.password, function (err, res) {
            console.log(result.value.password);
            if (res == true) {
              var user = result.value;
              bcrypt.genSalt(10, function (err, salt) {
                if (err) { console.log(err); }
                else {
                  bcrypt.hash(request.payload.password, salt, null, function (err, hash) {
                    if (err) { console.log(err); }
                    else {
                      user.password = hash;
                      apiUsers.replace(request.payload.email, user, function (err, res) {
                        if (err) {
                          console.log(err);
                          reply(err);
                        }
                        else {
                          console.log(res);
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