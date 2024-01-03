import { Fido2Lib } from 'fido2-lib';


//Tudo funcionando... amanhã é hora de organizar o código pra ficar bonito!!!
export const postFidoRegistrationOptions = async function(payload, db) {
    console.log("payload recebido", payload);
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
    //A documentação dos 3 campos abaixo está em https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html#attestationResult
    attestationOpts.challenge = base64ToArrayBuffer(attestationOpts.challenge);
    attestationOpts.factor = "either";
    attestationOpts.origin = "https://fido2-client.ranieri.dev.br"; //Substituir por um atributo que deve vir do request (ex: payload.origin)

    payload.attestationResult.rawId = base64ToArrayBuffer(payload.attestationResult.rawId);

    try {
        const registrationResult = await fidoInstance.attestationResult(payload.attestationResult, attestationOpts);
        console.log("resultado do registro:", registrationResult);

        //Isso deve ficar em outro método depois
        const authnOptions = await fidoInstance.assertionOptions();
        console.log("authnOptions", authnOptions);

        const response = {
            challenge: arrayBufferToBase64(authnOptions.challenge),
            allowCredentials: [{
                id: arrayBufferToBase64(registrationResult.request.rawId),
                type: registrationResult.request.response.type,
            }]
        }

        
        response.publicKey = registrationResult.authnrData.get("credentialPublicKeyPem");
        response.prevCounter = registrationResult.authnrData.get("counter");
        console.log("response para sign", response);
        db.save("login", response);
        return response;

    } catch (e) {
        console.log("erro no registro: ", e);
    }
}

export const postFidoSign = async function(payload, db) {
    const fidoInstance = createFidoInstance(payload);
    const assertion = db.get("login");
    const assertionExpectations = {...assertion,
        origin: "https://fido2-client.ranieri.dev.br", //Substituir por um atributo que deve vir do request (ex: payload.origin)
        factor: "either"
        
        //prevCounter: 362
    };
    assertionExpectations.challenge = base64ToArrayBuffer(assertionExpectations.challenge);
    assertionExpectations.userHandle = null;
    payload.auth.rawId = base64ToArrayBuffer(payload.auth.rawId);
    console.log(payload.auth)

    try {
        const authnResult = await fidoInstance.assertionResult(payload.auth, assertionExpectations); // will throw on error
        
        console.log("sucesso na auth");
        console.log(authnResult)
        return { "ok":"ok" };

    } catch (e) {
        console.log("Erro ao tentar autehtnicar: ", e);
    }
}

export const postFidoSignOptions = async function(payload, db) {
    const fidoInstance = createFidoInstance(payload);
    const attestationOpts = await fidoInstance.attestationOptions();
    //Converte o challenge para base64 para possibilitar o envio via JSON
    attestationOpts.challenge = arrayBufferToBase64(attestationOpts.challenge);
    db.save(`${payload.enrollmentId}-attestationOpts`, attestationOpts);
    return attestationOpts;
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
    //A documentação dos parâmetros possíveis pode ser encontrada em https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html

    const fidoInstance = new Fido2Lib({
        rpId: params.rp,
        //rpName: "Ranieri",
        challengeSize: 128,
        attestation: "direct",
        //-7: Certificados do tipo ES256 - Geralmente utilizando por mobiles
        //-257: Certificados do tipo RS256 - Geralmente utilizado por chaves externas (usb)
        cryptoParams: [-7, -257],
        //Torna obrigatório a validação do cliente tanto para registro do dispositivo quanto para autenticação
        authenticatorUserVerification: "required", //O ideal é sempre ser required para obrigar a validação do usuário para a criação
        authenticatorAttachment: ['ANDROID','IOS'].includes(params.platform) ? 'platform' : 'cross-platform',
        authenticatorRequireResidentKey: true,
        //authenticatorUserVerification: "required"
        /*authenticatorSelection: {
            residentKey: "preferred",
            requireResidentKey: false,
            userVerification: "required",
            authenticatorAttachment: ['ANDROID','IOS'].includes(params.platform) ? 'platform' : 'cross-platform'
        }*/
    });

    return fidoInstance;
}