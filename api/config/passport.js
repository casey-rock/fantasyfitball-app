/*
Passport is a Node module that simplifies the process of handling authentication in Express.
It provides a common gateway to work with many different authentication “strategies”,
such as logging in with Facebook, Twitter or Oauth. The strategy we’ll use is called “local”,
as it uses a username and password stored locally.
*/
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var mongoose = require('mongoose');
var User = mongoose.model('User');
