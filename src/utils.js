import base64 from "@hexagon/base64";

export const buildAttestation = function(attestation) {
    let newAttestation = {...attestation};
    delete(newAttestation.enrollmentId);
    delete(newAttestation.id);
    newAttestation.rawId = base64.toArrayBuffer(newAttestation.rawId, true);
    //TODO verificar se caso seja ANDROID ou IOS, isso pode ser internal apenas
    newAttestation.transports = ['hybrid','internal'];

    return newAttestation;
}

export const buildAttestationExpectation = function(attestation, attestationExpectation) {
    //TODO talvez o melhor seja que o origin seja enviado no request payload ao invés de fazer a extração aqui
    //Assim isso já fica na camada de negócio, já que lá também será necessário fazer essa extração
    const origin = extractOriginFromClientDataJSON(attestation.response.clientDataJSON);
    let newAttestationExpectation = {...attestationExpectation, origin};
    return newAttestationExpectation;
}

export const extractOriginFromClientDataJSON = function (clientDataJSON) {
    const clientDataJSONArrBuf = base64.toArrayBuffer(clientDataJSON, true);
    const uint8Array = new Uint8Array(clientDataJSONArrBuf);
    const utf8Decoder = new TextDecoder('utf-8');
    const jsonString = utf8Decoder.decode(uint8Array);
    const jsonObject = JSON.parse(jsonString);
    
    return jsonObject.origin;
}