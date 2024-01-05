import { Fido2Lib } from 'fido2-lib';
import randomstring from 'randomstring';

export const postFidoRegistrationOptions = async function(payload, db) {
    try {
        const currentDate = new Date();
        
        const fidoObject = {
            registration: {
                rp: payload.rp,
                platform: payload.platform,
                origin: payload.origin,
                date: currentDate.toISOString()
            }
        }
        
        const fidoInstance = createFidoInstance(fidoObject.registration.rp, fidoObject.registration.platform);
        
        const attestationOpts = await fidoInstance.attestationOptions();
        //Converte o challenge para base64 para possibilitar o envio via JSON
        attestationOpts.challenge = arrayBufferToBase64(attestationOpts.challenge);
        const userId = randomstring.generate({length: 32, charset: 'alphanumeric'});
        attestationOpts.user = {
            id: userId
        }

        //Complementa o objeto de attestation e salva no DB para validação futura quando o postFidoRegistration for chamado
        fidoObject.registration.attestationExpectation = {
            ...attestationOpts,
            factor: 'either',
            origin: fidoObject.registration.origin
        };
        await db.saveFidoObject(payload.id, fidoObject);
        console.log("DEBUG - fidoObject: ", JSON.stringify(fidoObject));
        return attestationOpts;
    } catch (e) {
        console.log(e);
        return null;
    }
}

export const postFidoRegistration = async function(payload, db) {
    try {
        let fidoObject = await db.getFidoObjectById(payload.id);
        const fidoInstance = createFidoInstance(fidoObject.registration.rp, fidoObject.registration.platform);
        
        //Converte o challenge e o rawId de volta para ArrayBuffer para conseguir realizar o attestation
        const attestationExpectation = {...fidoObject.registration.attestationExpectation};
        //attestationExpectation.challenge = base64ToArrayBuffer(attestationExpectation.challenge); //Não converter de volta ou converter para base64url neste momento
        payload.attestationResult.rawId = base64ToArrayBuffer(payload.attestationResult.rawId);
        
        //Teste de results
        payload.attestationResult.transports = ['hybrid','internal'];
    
        //Valida o registro do cliente
        const registrationResult = await fidoInstance.attestationResult(payload.attestationResult, attestationExpectation);

        //Salva os dados do registro para realização de futuras autenticações
        const currentDate = new Date();
        fidoObject.registration.attestationResult = {
            publicKey: registrationResult.authnrData.get("credentialPublicKeyPem"),
            prevCounter: registrationResult.authnrData.get("counter"),
            id: arrayBufferToBase64(registrationResult.request.rawId),
            type: registrationResult.request.response.type,
            date: currentDate.toISOString()
        };
        console.log("resultado do registro:", registrationResult);
        await db.saveFidoObject(payload.id, fidoObject);
        console.log("DEBUG - fidoObject: ", JSON.stringify(fidoObject));

        return;
    } catch (e) {
        console.log("erro no registro: ", e);
    }
}

export const postFidoSignOptions = async function(payload, db) {
    try {
        let fidoObject = await db.getFidoObjectById(payload.id);
        const fidoInstance = createFidoInstance(fidoObject.registration.rp, payload.platform);
        
        //Cria o objeto de assertion a ser retornado para RP
        const authnOptions = await fidoInstance.assertionOptions();
        const response = {
            challenge: arrayBufferToBase64(authnOptions.challenge),
            allowCredentials: [{
                id: fidoObject.registration.attestationResult.id,
                type: fidoObject.registration.attestationResult.type
            }]
        }

        //Salva o objeto de assertion para ser comparado no momento do postFidoSign
        fidoObject.assertion = {
            ...response,
            prevCounter: fidoObject.registration.attestationResult.prevCounter,
            publicKey: fidoObject.registration.attestationResult.publicKey,
            factor: "either",
            origin: fidoObject.registration.origin,
            userHandle: null, //depois colocar o user.id para ver o que acontece
            platform: payload.platform
        }
        db.saveFidoObject(payload.id, fidoObject);
        return response;
    } catch(e) {
        console.log(e);
        return null;

    }
}

export const postFidoSign = async function(payload, db) {
    try {
        let fidoObject = await db.getFidoObjectById(payload.id);
        const fidoInstance = createFidoInstance(fidoObject.registration.rp, fidoObject.assertion.platform);
        
        const assertionExpectations = {...fidoObject.assertion};
        assertionExpectations.challenge = base64ToArrayBuffer(assertionExpectations.challenge);

        payload.assertion.rawId = base64ToArrayBuffer(payload.assertion.rawId);

        const authnResult = await fidoInstance.assertionResult(payload.assertion, assertionExpectations);
        console.log("sucesso na auth");
        console.log(authnResult)
        return { "ok":"ok" }; 
    } catch(e) {
        console.log(e);
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

const createFidoInstance = function(rp, platform) {
    //A documentação dos parâmetros possíveis pode ser encontrada em https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html
    const fidoInstance = new Fido2Lib({
        rpId: rp.id,
        rpName: rp.name,
        challengeSize: 128,
        attestation: "direct",
        //-7: Certificados do tipo ES256 - Geralmente utilizando por mobiles
        //-257: Certificados do tipo RS256 - Geralmente utilizado por chaves externas (usb)
        cryptoParams: [-7, -257],
        authenticatorAttachment: ['ANDROID','IOS'].includes(platform) ? 'platform' : 'cross-platform',
        authenticatorRequireResidentKey: true,
        authenticatorUserVerification: "required"
    });

    return fidoInstance;
}