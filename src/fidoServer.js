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
    attestationOpts.challenge = coerceToBase64(attestationOpts.challenge, "challenge");
    db.save(`${payload.enrollmentId}-attestationOpts`, attestationOpts);
    return attestationOpts;
}

export const postFidoRegistration = async function(payload, db) {
    const fidoInstance = createFidoInstance(payload);
    const attestationOpts = db.get(`${payload.enrollmentId}-attestationOpts`);
    //Converte o challenge para ByteArray para possibilitar a validação do attestation
    attestationOpts.challenge = coerceToArrayBuffer(attestationOpts.challenge, "challenge");

    try {
        const registrationResult = await fidoInstance.attestationResult(payload.attestationResult, attestationOpts);
        console.log(registrationResult);
    } catch (e) {
        console.log(e);
    }
    
}

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