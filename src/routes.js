import express from 'express';
import * as fidoServer from './fidoServer.js';
import MemoryAdapter from './persistence.js';
import { validateRequest } from './validations.js';

const router = express.Router();

const db = new MemoryAdapter();

//IMPORTANTE: A especificação das API's FIDO do Open Finance dizem que o atributo de resposta rp.id 
//deve a CN recebida no atributo rp da requisição. Isso pode funcionar para RP's que são apenas web
//pois a CN é no formato https://dominio.com.br, porém para RP's que também possuem app, é possível
//que o aplicativo esteja esperando a resposta rp.id no formato de application_id/bundle_id 
//(com.example.myapp), o que pode ocasionar a impossibilidade de registro do dispositivo.
router.post('/fido-registration-options', async (req, res) => {
    try {
        //Valida se todos os campos obrigatórios foram enviados
        const mandatoryFields = ["enrollmentId","rpName","rpId","platform"];
        validateRequest(req.body, mandatoryFields);

        //Cria o attestion no servidor FIDO e salva no BD
        const [attestationOpts, fidoObject] = await fidoServer.postFidoRegistrationOptions(req.body);
        await db.save(req.body.enrollmentId, fidoObject);

        res.status(201)
            .type('application/json')
            .send(attestationOpts);
    } catch (e) {
        console.log("Erro na chamada ao endpoint POST /fido-registration-options do FIDO Server: ", e);

        res.status(400)
            .type('plain/text')
            .send(e.message);
    }
});

router.post('/fido-registration', async (req, res) => {
    try {
        //Valida se todos os campos obrigatórios foram enviados
        const mandatoryFields = ["id", "rawId", "response.attestationObject", "response.clientDataJSON", "response.type", "enrollmentId"];
        validateRequest(req.body, mandatoryFields);

        //Valida o attestation do dispositivo do cliente
        let fidoObject = await db.get(req.body.enrollmentId);
        fidoObject = await fidoServer.postFidoRegistration(fidoObject, req.body);
        await db.save(req.body.enrollmentId, fidoObject);
            
        res.status(201).send();
    } catch (e) {
        console.log("Erro na chamada ao endpoint POST /fido-registration do FIDO Server: ", e);

        res.status(400)
            .type('plain/text')
            .send(e.message);
    }
});

router.post('/fido-sign-options', async (req, res) => {
    try {
        //Valida se todos os campos obrigatórios foram enviados
        const mandatoryFields = ["rpName","rpId", "platform", "enrollmentId"];
        validateRequest(req.body, mandatoryFields);

        //Cria o assertion no servidor FIDO e salva no BD        
        let assertionOptions, fidoObject;
        fidoObject = await db.get(req.body.enrollmentId);
        [assertionOptions, fidoObject] = await fidoServer.postFidoSignOptions(fidoObject, req.body);
        await db.save(req.params.enrollmentId, fidoObject);

        res.status(201)
            .type('application/json')
            .send(JSON.stringify(assertionOptions));
    } catch (e) {
        console.log("Erro na chamada ao endpoint POST /fido-sign-options do FIDO Server: ", e);

        res.status(400)
            .type('plain/text')
            .send(e.message);
    }
    
});

router.post('/fido-sign', async (req, res) => {
    try {
        //Valida se todos os campos obrigatórios foram enviados
        const mandatoryFields = ["assertion.id", "assertion.rawId", "assertion.response.authenticatorData", "assertion.response.clientDataJSON", "assertion.response.signature", "assertion.type", "enrollmentId"];
        validateRequest(req.body, mandatoryFields);

        //Realiza a autenticação do cliente
        let fidoObject = await db.get(req.body.enrollmentId);
        const assertion = await fidoServer.postFidoSign(fidoObject, req.body);
            
        res.status(200).send();
    } catch (e) {
        console.log("Erro na chamada ao endpoint POST /fido-sign do FIDO Server: ", e);

        res.status(400)
            .type('plain/text')
            .send(e.message);
    }
});

export default router;