/**
 * Module for bootstrapping application configuration and handling secrets from Vault.
 */

let jobsProxyConfig = {};
const fs = require('fs');
const {format} = require('logform');
const winston = require('winston');

/**
 * Bootstraps the application configuration by loading secrets from Vault if provided.
 *
 * @param {Object} app - The application instance.
 * @returns {Promise} - A promise that resolves with the configuration or null.
 */
module.exports.bootstrapConfiguration = function (app) {
    const argv = require('yargs').argv;

    return new Promise(function (resolve, reject) {
        require('dotenv').config({path: "default.env"});

        if (argv.vaultToken && argv.vaultUrl && argv.vaultPath) {
            loadSecretsIntoEnv(argv.vaultUrl, argv.vaultToken, argv.vaultPath, argv.debugMode).then(config => {
                resolve(config);
            }, error => {
                logger.error("Unable to load secrets from vault");
                reject(error);
            });
        } else {
            logger.info("No vault configuration found");
            resolve(null);
        }
    });
};

/**
 * Loads secrets from Vault into environment variables.
 *
 * @param {string} vaultUrl - The URL of the Vault server.
 * @param {string} vaultToken - The token for authenticating with Vault.
 * @param {string} vaultPath - The path in Vault where secrets are stored.
 * @param isDebugMode - A flag indicating whether debug mode is enabled.
 * @returns {Promise} - A promise that resolves with the configuration or rejects with an error.
 */
let loadSecretsIntoEnv = function (vaultUrl, vaultToken, vaultPath, isDebugMode) {
    return new Promise(function (resolve, reject) {
        let vaultClient = require("node-vault-client");
        console.log('[APP-CFG] - Vault token load:: OK');
        if(isDebugMode) {
            console.log(`[APP-CFG] - Vault token value:: ${vaultToken}`);
        }

        vaultClient = vaultClient.boot('main', {
            api: {url: vaultUrl},
            auth: {
                type: 'token',
                config: {token: vaultToken}
            },
        });

        vaultClient.read(vaultPath).then(v => {
            let vaultValues = v.__data.data;
            for (let key in vaultValues) {
                process.env[key] = vaultValues[key];
            }
            if (vaultValues !== undefined) {
                logger.info("Loaded secrets from vault");
                const config = require('config');
                resolve(config);
                if (isDebugMode) printVaultValues(vaultValues);
            }
        }).catch(e => {
            logger.error("Unable to load secrets from vault", error);
            reject("Unable to load secrets from vault", error);
            console.error(e)
        });
    });
};

/**
 * Creates a logger instance using Winston.
 *
 * @returns {Object} - A Winston logger instance.
 */
module.exports.getLoggerApp = function () {
    return winston.createLogger({
        format: format.combine(
            format.json(),
            format.timestamp(),
        ),
        transports: [
            new winston.transports.Console()
        ]
    });
};

/**
 * Reads and parses the jobs proxy configuration from a JSON file.
 */
module.exports.createDirectoryProxyConfig = function () {
    const configJson = fs.readFileSync('server/config/config.json', 'utf8');
    const config = JSON.parse(configJson);
    jobsProxyConfig = config['directoryBackendProxyConfig'];
    logger.info("[DS] - Proxy Config: " + JSON.stringify(jobsProxyConfig));
};

/**
 * Retrieves the jobs proxy configuration.
 *
 * @returns {Object} - The jobs proxy configuration.
 */
module.exports.getJobsProxyConfig = function () {
    return jobsProxyConfig;
};

let printVaultValues = function (vaultValues) {
    logger.info("<><><><><><><><><><><><><><> Vault values <><><><><><><><><><><><><><>");
    for (let key in vaultValues) {
        logger.info(`${key}: ${vaultValues[key]}`);
    }
    logger.info("<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>");
}

const logger = this.getLoggerApp();
