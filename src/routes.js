import express from 'express';
import { postFidoRegistration, postFidoRegistrationOptions, postFidoSign, postFidoSignOptions } from './fidoServer.js';
import MemoryAdapter from './persistence.js';

const router = express.Router();
const db = new MemoryAdapter();

router.post('/fido-registration-options', async (req, res) => {
    const response = await postFidoRegistrationOptions(req.body, db);
        
    res.status(201)
        .type('application/json')
        .send(response);
    
});

router.post('/fido-registration', async (req, res) => {
    const response = await postFidoRegistration(req.body, db);
        
    res.status(200)
        .type('application/json')
        .send(JSON.stringify(response));
    
});

router.post('/fido-sign-options', async (req, res) => {
    const response = await postFidoSignOptions(req.body, db);
        
    res.status(200)
        .type('application/json')
        .send(JSON.stringify(response));
    
});

router.post('/fido-sign', async (req, res) => {
    const response = await postFidoSign(req.body, db);
        
    res.status(200)
        .type('application/json')
        .send(JSON.stringify(response));
    
});

export default router;