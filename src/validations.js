export const validateRequest = function (req, expectedKeys) {
    for (let key of expectedKeys) {
        if (!getValue(req, key)) {
            throw new Error("Campo obrigatório não enviado: " + key);
        }
    }
    return true;
}

const getValue = function (obj, path) {
    const keys = path.split('.');
    for (let key of keys) {
        if (obj && obj.hasOwnProperty(key)) {
            obj = obj[key];
        } else {
            return false;
        }
    }
    return obj;
}