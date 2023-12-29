import express from 'express';
import https from 'https';
import * as selfsigned from 'selfsigned';
import config from './config.js';
import routes from './routes.js';

const app = express();

//Gera certificados auto-assinados para localhost
const attrs = [{ name: 'commonName', value: config.hostname }];
const hostCerts = selfsigned.generate(attrs, { days: 365, keySize: 2048 });

const options = {
    key: hostCerts.private,
    cert: hostCerts.cert,
    requestCert: true,
    rejectUnauthorized: false
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/', routes);

const server = https.createServer(options, app);

server.listen(config.serverPort, () => {
    console.log(`Server listening at https://${config.hostname}:${config.serverPort}`);
});


// could also use one or more of the options below,
// which just makes the options calls easier later on:
/*const f2l = new Fido2Lib({
    timeout: 42,
    rpId: "ranieri.dev.br",
    rpName: "Ranieri",
    rpIcon: "https://example.com/logo.png",
    challengeSize: 128,
    attestation: "none",
    cryptoParams: [-7, -257], //ES256 e RS256
    authenticatorAttachment: "platform", //cross-platform deve ser o mais indicado para permitir usb e mobile devices
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "required"
});*/


//const registrationOptions = await f2l.attestationOptions();
//console.log(registrationOptions);
// make sure to add registrationOptions.user.id
// save the challenge in the session information...
// send registrationOptions to client and pass them in to `navigator.credentials.create()`...
// get response back from client (clientAttestationResponse)

/*const attestationExpectations = {
    challenge: "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w",
    origin: "https://localhost:8443",
    factor: "either"
};*/

/*const clientAttestationResponse = {
    id: "abc123", // Um identificador único gerado pelo cliente
    type: "public-key",
    rawId: "vGhNeEhQKkJ7H8aZYxgOwtNMwQTa3pXEnQeXuhcnmHA", // Base64URL-encoded raw ID gerado pelo cliente
  
    response: {
      clientDataJSON: "eyJjaGFsbGVuZ2UiOiJhbm9ueW1vdXNlIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJhcHBsaWNhdGlvbi9qc29uIiwidHlwZSI6InB1YmxpYy1rZXkifQ==", // Base64URL-encoded JSON gerado pelo cliente
      attestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0b3JlA...oCE1fSBijCCBHYwggRpoAMCA...BAgMEBQYHCAECAwQFBgcIAQIDAgQCBgcDBAUGBwgBAgMEBQYHCAECAwQFBgcIAQIDAgQCBgcDBAYH", // Base64URL-encoded objeto de atestação gerado pelo cliente
    },
  };

const regResult = await f2l.attestationResult(clientAttestationResponse, attestationExpectations); // will throw on error

console.log(regResult);*/
// registration complete!
// save publicKey and counter from regResult to user's info for future authentication calls