const assert = require('assert');
const axios = require('axios');
const {BEARER} = require("../config/constants.util");

/**
 * BackboneClient class to interact with the backbone API to get the
 * token for the user to access the API endpoints in the backbone.
 */
class BackboneClient {

    /**
     * Constructor for BackboneClient class.
     * @param config - Configuration object for the backbone API.
     */
    constructor(config) {
        assert.ok(config, "BackboneClient: config is not defined");
        assert.ok(config.url, "BackboneClient: config.url is not defined");

        this.url = config.url;
    }

    /**
     * Get the token from the backbone API for the user to access the API endpoints.
     * @param user - User alias to get the token.
     * @param password - Password for the user.
     * @param bearerToken - Bearer token to access the backbone API.
     * @returns {Promise<any>} - Promise object represents the token.
     */
    getToken = async (user, password, bearerToken) => {
        let options = {
            method: "POST",
            headers: {
                'Content-Type': 'application/json',
                'Authorization': BEARER + bearerToken
            },
            data: {
                'alias': user,
                'password': password
            },
            url: this.url
        }

        const backboneResponse = await axios(options);
        return backboneResponse.data;
    };
}

/**
 * Retrieves the API endpoint for a given path.
 * @param backboneConfig - Backbone configuration object.
 * @returns {BackboneClient} - BackboneClient object.
 */
module.exports.getBackbone = function (backboneConfig) {
    return new BackboneClient(backboneConfig);
};