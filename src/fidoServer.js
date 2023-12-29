import { Fido2Lib } from 'fido2-lib';
import { coerceToBase64, coerceToBase64Url,coerceToArrayBuffer } from 'fido2-lib/lib/utils.js';


/*
export const createAttestationForEnrollment = function() {
    
    //const registrationOptions = await f2l.attestationOptions(); Talvez o attestationOptions tenha que ser enviado tb;
    const challenge = randomBytes(128);

    const attestationExpectations = {
        challenge: challenge.toString('base64'),
        origin: "https://localhost:8443",
        factor: "either"
    };

    //save it

    //return it
    return attestationExpectations;
}

export const validateAttestationForEnrollment = async function() {
    //get attestation expectation
    try {
        const regResult = await fido2Server.attestationResult(clientAttestationResponse, attestationExpectations); // will throw on error
    } catch (e) {
        console.log("erro: validateAttestationForEnrollment", e);
    }
}*/

export const postFidoRegistrationOptions = async function(payload, db) {
    const fidoInstance = createFidoInstance(payload);
    const attestationOpts = await fidoInstance.attestationOptions();
    //Converte o challenge para base64 para possibilitar o envio via JSON
    attestationOpts.challenge = arrayBufferToBase64(attestationOpts.challenge);
    db.save(`${payload.enrollmentId}-attestationOpts`, attestationOpts);
    return attestationOpts;
}

export const postFidoRegistration = async function(payload, db) {
    const fidoInstance = createFidoInstance(payload);
    const attestationOpts = db.get(`${payload.enrollmentId}-attestationOpts`);
    //Converte o challenge para ByteArray para possibilitar a validação do attestation
    attestationOpts.challenge = base64ToArrayBuffer(attestationOpts.challenge);
    attestationOpts.factor = "either";
    attestationOpts.origin = "https://fido2-client.ranieri.dev.br";
    payload.attestationResult.rawId = base64ToArrayBuffer(payload.attestationResult.rawId);

    try {
        const registrationResult = await fidoInstance.attestationResult(payload.attestationResult, attestationOpts);
        console.log("resultado do registro:", registrationResult);
    } catch (e) {
        console.log("erro no registro: ", e);
    }
    
}

function base64ToArrayBuffer(base64String) {
    // Step 1: Convert Base64 to Buffer
    const buffer = Buffer.from(base64String, 'base64');

    // Step 2: Convert Buffer to Uint8Array
    const uint8Array = new Uint8Array(buffer);

    // Step 3: Convert Uint8Array to ArrayBuffer
    const arrayBuffer = uint8Array.buffer;

    return arrayBuffer;
}

function arrayBufferToBase64(arrayBuffer) {
    // Step 1: Convert ArrayBuffer to Buffer
    const buffer = Buffer.from(arrayBuffer);

    // Step 2: Convert Buffer to Base64
    const base64 = buffer.toString('base64');

    return base64;
}

/*
const base64urlToArrayBuffer = function(base64url) {
    // Step 1: Add padding to the Base64url string if necessary
    const paddedBase64 = base64url + '='.repeat((4 - base64url.length % 4) % 4);

    // Step 2: Decode Base64 to Buffer
    const buffer = Buffer.from(paddedBase64, 'base64');

    // Step 3: Convert Buffer to Uint8Array
    const uint8Array = new Uint8Array(buffer);

    // Step 4: Convert Uint8Array to ArrayBuffer
    const arrayBuffer = uint8Array.buffer;

    return arrayBuffer;
}

const arrayBufferToBase64url = function(arrayBuffer) {
    // Step 1: Convert ArrayBuffer to Buffer
    const buffer = Buffer.from(arrayBuffer);

    // Step 2: Convert Buffer to Base64
    const base64 = buffer.toString('base64');

    // Step 3: Make Base64 URL-safe
    const base64url = base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

    return base64url;
}*/

const createFidoInstance = function(params) {
    const fidoInstance = new Fido2Lib({
        //timeout: 42,
        rpId: params.rp,
        //rpName: "Ranieri",
        //rpIcon: "https://example.com/logo.png",
        challengeSize: 128,
        attestation: "none", //Verificar
        cryptoParams: [-7, -257], //ES256 e RS256 (mobile usa es256 e chave usb usa rs256)
        //TODO talvez o melhor seja não definir o parametro abaixo, pois assim o dispositivo do cliente pode decidir o que usar, por exemplo, uma chave que permita NFC no celular
        //authenticatorAttachment: ["ANDROID","IOS"].includes(params.platform) ? 'platform' : 'cross-platform',
        authenticatorRequireResidentKey: false, //verificar
        authenticatorUserVerification: "required" //verificar
    });
    return fidoInstance;
}