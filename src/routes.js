import express from 'express';
import { postFidoRegistrationOptions } from './fidoServer.js';
import MemoryAdapter from './persistence.js';

const router = express.Router();
const db = new MemoryAdapter();

router.post('/fido-registration-options', async (req, res) => {
    const response = await postFidoRegistrationOptions(req.body, db);
        
    res.status(200)
        .type('application/json')
        .send(response);
    
});

export default router;