const assert = require('assert');
const axios = require('axios');
const AuthenticationType = {
  OPAQUE: "OPAQUE",
  JWT: "JWT"
}

/**
 * Class representing an OAuth client.
 */
class OAuthClient {
  clientId;
  clientSecret;
  grantType;
  tokenUrl;
  authenticationType;
  tokenCachePeriod = 1800;
  cacheToken;
  lastRequestTime = 0;

  /**
   * Creates an OAuth client.
   * @param {Object} config - The configuration object.
   * @param {string} config.clientId - The client ID.
   * @param {string} config.clientSecret - The client secret.
   * @param {string} config.grantType - The grant type.
   * @param {string} config.tokenUrl - The token URL.
   * @param {string} config.authenticationType - The authentication type.
   * @param {string} config.username - The username.
   * @param {string} config.password - The password.
   */
  constructor(config) {
    assert.ok(config, "OAuthClient: config is not defined");
    assert.ok(config.clientId, `OAuthClient: config.clientId is not provided for Auth Type: ${config.authenticationType}`);
    assert.ok(config.clientSecret, `OAuthClient: config.clientSecret is not provided for Auth Type: ${config.authenticationType}`);
    assert.ok(config.grantType, `OAuthClient: config.grantType is not provided for Auth Type: ${config.authenticationType}`);
    assert.ok(config.tokenUrl, `OAuthClient: config.tokenUrl is not provided for Auth Type: ${config.authenticationType}`);
    assert.ok(config.username, `OAuthClient: config.username is not provided for Auth Type: ${config.authenticationType}`);
    assert.ok(config.password, `OAuthClient: config.password is not provided for Auth Type: ${config.authenticationType}`);

    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.grantType = config.grantType;
    this.tokenUrl = config.tokenUrl;
    this.username = config.username;
    this.password = config.password;
    this.authenticationType = config.authenticationType;
  }

  /**
   * Retrieves the bearer token.
   * @returns {Promise<string>} The bearer token.
   */
  getBearerToken = async() => {
    const requestTime = new Date().getTime();
    if(this.cacheToken === undefined || this.cacheToken === "" || (requestTime - this.lastRequestTime) / 1000 > this.tokenCachePeriod) {
      let options = {};
      if(this.authenticationType === AuthenticationType.OPAQUE) {
        options = {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          data: new URLSearchParams({
            client_id: this.clientId,
            client_secret: this.clientSecret,
            grant_type: this.grantType,
            username:this.username,
            password:this.password
          }),
          url: this.tokenUrl
        };
      } else  {
        options = {
          method: "POST",
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          data: {
            grant_type: this.grantType,
            client_id: this.clientId,
            client_secret: this.clientSecret,
            username:this.username,
            password:this.password
          },
          url: this.tokenUrl
        };
      }

      // Call OAuth service
      const oauthResponse = await axios(options);
      // Cache token in local variable.
      this.cacheToken = oauthResponse.data.access_token;
      this.lastRequestTime = requestTime;
      return this.cacheToken;
    } else {
      return this.cacheToken;
    }
  };
}

/**
 * Retrieves an OAuth client instance.
 * @param {Object} oauthClientConfig - The OAuth client configuration.
 * @returns {OAuthClient} The OAuth client instance.
 */
module.exports.getOAuthClient = function(oauthClientConfig) {
  return new OAuthClient(oauthClientConfig);
}