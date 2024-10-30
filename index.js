'use strict';

let Crypto = require('node:crypto');

let E = require('libauth/lib/errors.js');

/**
 * @typedef GoHighLevelOAuth2Opts
 * @prop {String} clientId
 * @prop {String} clientSecret
 * @prop {String} redirectUri - URL path, or full URL
 * @prop {String} [providerHostname]
 * @prop {String} [providerBaseUrl]
 * @prop {Array<String>} [baseScopes]
 * @prop {String} [profileHostname]
 */

/**
 * @typedef AppLibAuthOpts
 * @prop {String} [issuer]
 * @prop {String} [loginUrl]
 */

/**
 * @param {any} libauth
 * @param {AppLibAuthOpts} libOpts
 * @param {GoHighLevelOAuth2Opts} pluginOpts
 */
function create(libauth, libOpts, pluginOpts) {
  let providerHostname = pluginOpts.providerHostname || 'gohighlevel.com';
  let providerBaseUrl =
    pluginOpts.providerBaseUrl || 'https://marketplace.gohighlevel.com';
  let profileHostname = pluginOpts.providerHostname || 'services.leadconnectorhq.com';
  let baseScope = pluginOpts.baseScopes || ['users.readonly'].join(' ');

  /** @type {import('express').Handler} */
  async function generateAuthUrl(req, res, next) {
    if (req.query.code || req.query.error) {
      next();
      return;
    }

    let redirectUri =
      libauth.get(req, 'redirectUri') ||
      pluginOpts.redirectUri ||
      req.originalUrl ||
      req.url;
    let redirectHost =
      libauth.get(req, 'redirectHost') || libOpts?.issuer || libauth.issuer;

    // SECURITY check redirectUri
    let hasProtocol = startsWithProto(redirectUri);
    if (!hasProtocol) {
      if (!startsWithProto(redirectHost)) {
        redirectHost = `https://${redirectHost}`;
      }
      redirectUri += stripTrailingSlash(redirectUri);
      redirectUri = `${redirectHost}${pluginOpts.redirectUri}`;
    }

    let state = Crypto.randomInt(Math.pow(2, 32) - 1).toString(16);
    let query = Object.assign(req.query, {
      response_type: 'code',
      redirect_uri: redirectUri,
      client_id: pluginOpts.clientId,
      scope: baseScope,
      state: state,
    });
    //@ts-expect-error
    let searchParams = new URLSearchParams(query);
    let search = searchParams.toString();

    // ex: https://marketplace.gohighlevel.com/oauth/chooselocation?response_type=code&...
    let url = `${providerBaseUrl}/oauth/chooselocation?${search}`;

    libauth.set(req, {
      strategy: 'oauth2',
      authUrl: url.toString(),
    });

    next();
  }

  /** @type {import('express').Handler} */
  async function redirectToAuthUrl(req, res, next) {
    let authUrl = libauth.get(req, 'authUrl');
    if (!authUrl) {
      next();
      return;
    }

    const HTTP_FOUND_TEMPORARY = 302;
    res.redirect(HTTP_FOUND_TEMPORARY, authUrl);
  }

  /** @type {import('express').Handler} */
  async function readCodeParams(req, res, next) {
    let clientId = pluginOpts.clientId;
    let clientSecret = pluginOpts.clientSecret;
    let code = req.query.code;

    let form = {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'authorization_code',
      code: code,
    };

    libauth.set(req, {
      strategy: 'oauth2_code',
      oauth2Request: form,
    });

    next();
  }

  /** @type {import('express').Handler} */
  async function requestToken(req, res, next) {
    let oauth2TokenRequest = libauth.get(req, 'oauth2Request');

    // TODO check state
    //let state = req.query.state;

    let query = new URLSearchParams(oauth2TokenRequest);
    let resp = await fetch(`https://${profileHostname}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: query,
    });
    /** @type {GoHighLevelTokenData} */
    let result = await resp.json();

    if (!resp.ok) {
      //@ts-expect-error
      let msg = result.message?.join(', ');
      //@ts-expect-error
      let err = new Error(`oauth2 token error(s): ${result.error}: ${msg}`);
      Object.assign(err, {
        status: 500,
        code: 'E_OAUTH2_CONFIG',
      });
      throw err;
    }

    libauth.set(req, {
      strategy: 'oauth2',
      oauth2TokenResponse: result,
    });

    next();
  }

  /** @type {import('express').Handler} */
  async function verifyToken(req, res, next) {
    /** @type {GoHighLevelTokenData} */
    let oauth2TokenResponse = libauth.get(req, 'oauth2TokenResponse');

    /** @type {String} */
    let token = oauth2TokenResponse?.access_token;
    if (!token) {
      token = req.headers.authorization || '';
      token = token.replace(/^Bearer /, '');
    }

    /** @type {String} */
    let userId = oauth2TokenResponse?.userId;
    if (!userId) {
      userId = req.query.userId?.toString() || '';
    }

    // TODO SECURITY: We need a guarantee that GoHighLevel verifies emails
    let profile = await getProfile(token, userId);

    if (!profile.email) {
      throw E.OIDC_UNVERIFIED_IDENTIFIER('email');
    }

    let _oauth2Data = {
      id: profile.id,
      sub: oauth2TokenResponse.userId,
      email: profile.email,
      email_verified: !!profile.email,
      iss: `https://${providerHostname}`,
      issuer: `https://${providerHostname}`,
      profile: profile,
    };
    //@ts-ignore
    req._oauth2 = _oauth2Data;

    let oauth2Data = {
      strategy: 'oauth2',
      given_name: profile.firstName,
      family_name: profile.lastName,
      email: profile.email,
      email_verified: !!profile.email,
      iss: _oauth2Data.iss,
      sub: oauth2TokenResponse.userId,
      id: profile.id,
      raw_profile: profile,
    };
    libauth.set(req, 'oauth2_profile', oauth2Data);

    next();
  }

  // // For redirecting the token directly back to the browser
  // /** @type {import('express').Handler} */
  // async function redirectToken(req, res) {
  //   let form = libauth.get(req, 'codeResponse');
  //   let search = new URLSearchParams(form).toString();

  //   let loginUrl = libOpts.loginUrl || libOpts.issuer; // TODO issuer may not be 1:1 with return url
  //   let url = new URL(
  //     `${loginUrl}#${search}&issuer=${providerHostname}&state=${req.query.state}`,
  //   );

  //   res.statusCode = 302;
  //   res.setHeader('Location', url.toString());
  //   res.end('<!-- Redirecting... -->');
  // }

  /**
   * @param {String} token
   * @param {String} userId
   * @returns {Promise<GoHighLevelProfile>}
   */
  async function getProfile(token, userId) {
    let resp = await fetch(`https://${profileHostname}/users/${userId}`, {
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28',
      },
    });
    if (!resp.ok) {
      let result = await resp.json();
      let err = new Error(`oauth2 profile error: ${result.message}`);
      Object.assign(err, {
        status: 500,
        code: 'E_OAUTH2_PROFILE',
      });
      throw err;
    }

    let profile = await resp.json();
    profile.email = profile.email?.toLowerCase(); // just in case
    return profile;
  }

  let routes = {
    generateAuthUrl,
    redirectToAuthUrl,
    //authorization: TODO_openAuthorizationDialog
    readCodeParams,
    requestToken,
    verifyToken,
  };

  return routes;
}

/**
 * @param {String} str
 */
function startsWithProto(str) {
  // https:// http:// app: custom-x:
  let colonAt = str.indexOf(':');
  if (colonAt < 1) {
    return false;
  }
  if (colonAt < 10) {
    return true;
  }
  return false;
}

/**
 * @param {String} str
 */
function stripTrailingSlash(str) {
  if (!str.endsWith('/')) {
    return str;
  }
  return str.slice(0, -1);
}

/**
 * See <https://highlevel.stoplight.io/docs/integrations/a815845536249-get-user#response-body>
 * @typedef GoHighLevelProfile
 * @prop {String} id
 * @prop {String} firstName
 * @prop {String} lastName
 * @prop {String} email
 * @prop {String} phone
 */

/**
 * See <https://highlevel.stoplight.io/docs/integrations/00d0c0ecaa369-get-access-token#response-body>
 * @typedef GoHighLevelTokenData
 * @prop {String} access_token
 * @prop {String} refresh_token
 * @prop {"Company"|"Location"|String} userType
 * @prop {String} locationId
 * @prop {String} companyId
 * @prop {Array<String>} approvedLocations
 * @prop {String} userId
 * @prop {String} planId
 */

module.exports.create = create;
