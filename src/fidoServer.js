import { Fido2Lib } from 'fido2-lib';
import randomstring from 'randomstring';
import * as utils from './utils.js'
import base64 from '@hexagon/base64';

export const postFidoRegistrationOptions = async function(payload) {
    //Cria o objeto inicial
    const fidoObject = {
        registration: {
            rp: {
                id: payload.rpId,
                name: payload.rpName
            },
            platform: payload.platform,
            date: (new Date()).toISOString()
        }
    };
    
    //Cria a instância do FIDO Server
    const fidoInstance = createFidoInstance(fidoObject.registration.rp, fidoObject.registration.platform);

    //Cria o attestation expectation, que é o objeto que será utilizado pelo dispostivo (mobile, usb-key) do cliente
    //para registro do dispositivo
    const attestationOpts = await fidoInstance.attestationOptions();
    attestationOpts.challenge = base64.fromArrayBuffer(attestationOpts.challenge, true);
    attestationOpts.user = {
        id: randomstring.generate({length: 32, charset: 'alphanumeric'}) //TODO validar se esse valor precisa ser transmitido em base64url
    };

    //Cria o objeto de retorno
    fidoObject.registration.attestationExpectation = {
        ...attestationOpts,
        factor: 'either',
    };

    return [attestationOpts, fidoObject];
}

export const postFidoRegistration = async function(fidoObject, payload) {
    //Cria a instância do FIDO Server
    const fidoInstance = createFidoInstance(fidoObject.registration.rp, fidoObject.registration.platform);
    
    //Constroi os objetos de attestation para validação
    const attestation = utils.buildAttestation(payload);
    const attestationExpectation = utils.buildAttestationExpectation(attestation, fidoObject.registration.attestationExpectation);
    
    //Valida o registro do cliente
    const registrationResult = await fidoInstance.attestationResult(attestation, attestationExpectation);

    //Salva os dados do registro para realização de futuras autenticações
    fidoObject.registration.attestationResult = {
        publicKey: registrationResult.authnrData.get("credentialPublicKeyPem"),
        prevCounter: registrationResult.authnrData.get("counter"),
        id: base64.fromArrayBuffer(registrationResult.request.rawId, true),
        type: registrationResult.request.response.type,
        date: (new Date()).toISOString(),
        origin: attestationExpectation.origin
    };

    return fidoObject;
}

export const postFidoSignOptions = async function(fidoObject, payload) {
    //Cria a instância do FIDO Server
    const fidoInstance = createFidoInstance(fidoObject.registration.rp, payload.platform);
    
    //Cria o objeto de assertion
    const assertionOptions = await fidoInstance.assertionOptions();

    //Cria o objeto de assertion que será retornada à RP para assinatura do device (mobile, usb-key) do cliente
    const response = {
        challenge: base64.fromArrayBuffer(assertionOptions.challenge, true),
        allowCredentials: [{
            id: fidoObject.registration.attestationResult.id,
            type: fidoObject.registration.attestationResult.type
        }]
    };

    //Salva o objeto de assertion para ser comparado no momento do postFidoSign
    fidoObject.assertion = {
        ...response,
        prevCounter: fidoObject.registration.attestationResult.prevCounter,
        publicKey: fidoObject.registration.attestationResult.publicKey,
        factor: "either",
        origin: fidoObject.registration.attestationResult.origin,
        userHandle: null, //TODO: depois colocar o user.id para ver o que acontece
        platform: payload.platform
    }

    return [response, fidoObject];
}

export const postFidoSign = async function(fidoObject, payload) {
    //Cria a instância do FIDO Server
    const fidoInstance = createFidoInstance(fidoObject.registration.rp, fidoObject.assertion.platform);
    
    //Monta o objeto de assertion a ser comparado com o objeto assinado pelo device (mobile, usb-key) do cliente
    const assertionExpectations = {...fidoObject.assertion};
    assertionExpectations.challenge = base64.toArrayBuffer(assertionExpectations.challenge, true);
    assertionExpectations.origin = utils.extractOriginFromClientDataJSON(payload.assertion.response.clientDataJSON);

    //Monta o objeto assinado pelo device (mobile, usb-key) do cliente para realizar a autenticação
    let assertion = {...payload.assertion};
    assertion.rawId = base64.toArrayBuffer(assertion.rawId, true);

    //Valida a autenticação
    const assertionResult = await fidoInstance.assertionResult(assertion, assertionExpectations);
    
    return assertionResult;
}

const createFidoInstance = function(rp, platform) {
    //A documentação dos parâmetros possíveis pode ser encontrada em https://webauthn-open-source.github.io/fido2-lib/Fido2Lib.html
    const fidoInstance = new Fido2Lib({
        //rpId: rp.id, //TODO se descomentar essa linha, o certificado de transporte precisa estar correto para CN. Exemplo: CN=https://fido-client.localhost:4100
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