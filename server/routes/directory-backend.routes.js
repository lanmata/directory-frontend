const express = require('express');
const router = express.Router();
const multer = require('multer');
const upload = multer({dest: 'uploads/', limits: {fileSize: 200*1024*1024}});

let jobsProxyController = require('../controller/directory-backend.controller');

 router.all('/api/v1*', jobsProxyController.proxyApi);

module.exports = router;
