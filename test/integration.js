var Code = require('code');
var Lab = require('lab');
var Hapi = require('hapi');

var lab = exports.lab = Lab.script();

var before = lab.before;
var describe = lab.describe;
var it = lab.it;
var expect = Code.expect;

var actionTokenAuth = require('../');

describe('action-token', function () {
    var privateKey = "hfjdfjweir234234knknefnsdfs";
    var server = new Hapi.Server({ debug: false });

    server.on('request-error', console.log);
    
    server.connection();

    before(function (done) {
        var okHandler = function (req, rep) { return rep('OK'); };

        server.register(actionTokenAuth, function (err) {

            expect(err).to.not.exist();
            server.auth.strategy('default', 'action-token', 'required', { key: privateKey });

            server.route([
                { method: 'GET', path: '/inQuery', handler: okHandler, config: { auth: { strategy: 'default', scope: 'reset-password' } } },
                { method: 'GET', path: '/inUrl/{token}', handler: okHandler, config: { auth: { strategy: 'default', scope: 'reset-password' } } }
                //{ method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } },
                //{ method: 'POST', path: '/tokenOptional', handler: tokenHandler, config: { auth: { mode: 'optional' } } },
                //{ method: 'POST', path: '/tokenScope', handler: tokenHandler, config: { auth: { scope: 'x' } } },
                //{ method: 'POST', path: '/tokenArrayScope', handler: tokenHandler, config: { auth: { scope: ['x', 'y'] } } },
                //{ method: 'POST', path: '/tokenArrayScopeA', handler: tokenHandler, config: { auth: { scope: ['x', 'y', 'a'] } } },
                //{ method: 'POST', path: '/double', handler: doubleHandler }
            ]);

            done();
        });
    });

    it('auths tokens in the url', function (done) {

        var token = actionTokenAuth.generateActionToken( 'reset-password', {}, { expiresInMinutes: 10, key: privateKey });

        var request = { method: 'GET', url: '/inUrl/' + token };

        server.inject(request, function (res) {

            expect(res.result).to.equal('OK');
            done();
        });
    });

    it('auths tokens in the query', function (done) {

        var token = actionTokenAuth.generateActionToken( 'reset-password', {}, { expiresInMinutes: 10, key: privateKey });

        var request = { method: 'GET', url: '/inQuery?token=' + token };

        server.inject(request, function (res) {

            expect(res.result).to.equal('OK');
            done();
        });
    });

    it('fails with no token', function (done) {

        var request = { method: 'GET', url: '/inQuery?token=' };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('fails with invalid token', function (done) {

        var request = { method: 'GET', url: '/inQuery?token=asdf' };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(400);
            done();
        });
    });

    it('fails with invalid scope', function (done) {
        var token = actionTokenAuth.generateActionToken( 'some-wrong-scope', {}, { expiresInMinutes: 10, key: privateKey });

        var request = { method: 'GET', url: '/inQuery?token=' + token };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(403);
            done();
        });
    });
});
