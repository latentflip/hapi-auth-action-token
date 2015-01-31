var Boom = require('boom');
var Hoek = require('hoek');
var jwt  = require('jsonwebtoken');

var internals = {};


exports.register = function (server, options, next) {

    server.auth.scheme('action-token', internals.implementation);
    next();
};

exports.generateToken = function (scope, data, config) {
    Hoek.assert(
        typeof scope === 'string' || Array.isArray(scope),
        "scope must be a string or array of strings"
    );
    Hoek.assert(
        (config && (
            typeof config.expiresInMinutes === 'number' ||
            expiresInMinutes === false)
        ),
        "config.expiresInMinutes is not optional, set to number or false for no expiration (not usually recommended)"
    );
    Hoek.assert(
        config && config.key,
        "config.key (privateKey) is required"
    );

    return jwt.sign({
        type: 'action-token',
        scope: Array.isArray(scope) ? scope : [scope],
        data: data
    }, config.key, {
        expiresInMinutes: config.expiresInMinutes
    });
};

exports.register.attributes = {
    pkg: require('./package.json')
};

internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing jwt auth strategy options');
    Hoek.assert(options.key, 'Missing required private key in configuration');

    var settings = Hoek.clone(options);
    internals.settings = settings;

    var scheme = {
        authenticate: function (request, reply) {
            var authorization = request.query.token || request.params.token;

            if (!authorization) {
                return reply(Boom.unauthorized(null, 'Bearer'));
            }

            var parts = ['Bearer', authorization];

            if (parts.length !== 2) {
                return reply(Boom.badRequest('Bad HTTP authentication header format', 'Bearer'));
            }

            if (parts[0].toLowerCase() !== 'bearer') {
                return reply(Boom.unauthorized(null, 'Bearer'));
            }

            if(parts[1].split('.').length !== 3) {
                return reply(Boom.badRequest('Bad HTTP authentication header format', 'Bearer'));
            }

            var token = parts[1];

            jwt.verify(token, settings.key, function(err, decoded) {
                if(err && err.message === 'jwt expired') {
                    return reply(Boom.unauthorized('Expired token received for JSON Web Token validation', 'Bearer'));
                } else if (err) {
                    return reply(Boom.unauthorized('Invalid signature received for JSON Web Token validation', 'Bearer'));
                }

                if (!settings.validateFunc) {
                    return reply.continue({ credentials: decoded });
                }
            });

        }
    };

    return scheme;
};
