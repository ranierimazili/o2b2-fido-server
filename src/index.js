import express from 'express';
import https from 'https';
import cors from 'cors';
import * as selfsigned from 'selfsigned';
import config from './config.js';
import routes from './routes.js';

const app = express();

//Gera certificados auto-assinados para localhost
const attrs = [{ name: 'commonName', value: config.hostname }];
const hostCerts = selfsigned.generate(attrs, { days: 3650, keySize: 2048 });

const options = {
    key: hostCerts.private,
    cert: hostCerts.cert,
};

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/fido-server', routes);

const server = https.createServer(options, app);

server.listen(config.serverPort, () => {
    console.log(`Server listening at https://${config.hostname}:${config.serverPort}`);
});