var crypto = require('crypto');
var jwt = require('jsonwebtoken');

  var userSchema = new mongoose.Schema({
    email: {
      type: String,
      unique: true,
      required: true
    },
    name: {
      type: String,
      required: true
    },
    hash: String,
    salt: String
  });

  userSchema.methods.setPassword = function(password){
    //generates cryptographically strong pseudo-random data x bytes long (16 here),
    //turns these bytes into a hexadecimal string, and assigns it to be our salt.
    this.salt = crypto.randomBytes(16).toString('hex');

    //creates a hash with the password and randomized salt above and the sha512
    //hash function
    this.hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64, 'sha512'.toString('hex'));
  };

  //takes the password given by the user, runs the pbkdf2Sync function with
  //the user's salt, runs the same encryption algorithm as above, and compares.
  //If this hash is equal to the hash we have stored for the user, the pw must be correct
  userSchema.methods.validPassword = function(password) {
    var hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64, 'sha512').toString('hex');
    return this.hash === hash;
  };

  userSchema.methods.generateJwt = function(){
    //creates an "expiry" variable equal to the current date and time
    var expiry = new Date();
    //sets the expiry to the current date and time + 7 ("one week from now, this will expire")
    expiry.setDate(expiry.getDate() + 7);

    //jsonwebtoken module has a "sign" method we can use to create a jwt plus a secret that
    //the hashing algorithm will use.
    //a JWT is much more obfuscated than a password, pretty huge
    //they have to be sent with every API call but they're a LOT more secure, it's like a security pass 
    return jwt.sign({
      _id: this._id,
      email: this.email,
      name: this.name,
      exp: parseInt(expiry.getTime() / 1000),
    }, "MY_SECRET"); //It’s best practice to set the secret as an environment variable, and not have it in the source code, especially if your code is stored in version control somewhere.
    //****MAY HAVE TO EDIT THIS AND MAKE AN ENV FILE**********
  };

}
