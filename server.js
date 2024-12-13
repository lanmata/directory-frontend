process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
process.env.NODE_CONFIG_DIR = __dirname + "/server/config";

const httpContext = require('express-http-context');
const express = require('express');
const path = require('path');
const https = require('https');
const bodyParser = require('body-parser');
const appConfig = require('./server/config/app.config');
const compression = require('compression');
const app = express();
const cors = require('cors');
const fs = require('fs');
const RateLimit = require('express-rate-limit');

const options = {
  key: fs.readFileSync('./ssl/manager-front.key'),
  cert: fs.readFileSync('./ssl/manager-front.crt')
}

// set up rate limiter: maximum of 100 requests per 15 minutes
const limiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
});

app.use(httpContext.middleware);

let logger = appConfig.getLoggerApp();
// Parsers for POST data
app.use(limiter);
app.use(compression());
app.use(bodyParser.json({limit: '50mb'}));
app.use(cors());

// Get port from environment and store in Express.
const port = '7001';
app.set('port', port);

// Call bootstrap method which calls iConfig
appConfig.bootstrapConfiguration(app).then(
  config => {
    appConfig.createDirectoryProxyConfig();

    app.use("/", require("./server/routes/directory-backend.routes"));
    app.use(express.static("dist/directory-frontend/browser"));
    app.get("/*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist/directory-frontend/browser", "index.html"));
    });
  },
  err => {
    logger.error("Error in bootstrapping application", err);
  }
);

const server = https.createServer(options, app);

server.listen(port, () => logger.info(`UI running on localhost:${port}`));
