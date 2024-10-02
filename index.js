const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const port = 3000; // Porta em que o servidor irá rodar

// Chave de API correta
const API_KEY = '1234567890abcdef';

app.use(express.json());
app.use(cors());

// Middleware para autenticar a chave de API
const authenticateAPIKey = (req, res, next) => {
    const apiKey = req.header('x-api-key');
    if (!apiKey) {
        return res.status(401).json({ message: 'Chave de API ausente.' });
    }
    if (apiKey !== API_KEY) {
        return res.status(403).json({ message: 'Chave de API inválida.' });
    }
    next();
};

// Usando o middleware para proteger as rotas
app.use(authenticateAPIKey);

const algorithm = 'aes-256-cbc';
const secretKey = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// Endpoint para criptografar
app.post('/encrypt', (req, res) => {
    const { message } = req.body;
    if (!message) {
        return res.status(400).json({ message: 'Mensagem ausente.' });
    }
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    let encryptedMessage = cipher.update(message, 'utf-8', 'hex');
    encryptedMessage += cipher.final('hex');
    res.status(200).json({ encryptedMessage });
});

// Endpoint para descriptografar
app.post('/decrypt', (req, res) => {
    const { encryptedMessage } = req.body;
    if (!encryptedMessage) {
        return res.status(400).json({ message: 'Mensagem criptografada ausente.' });
    }
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf-8');
    decryptedMessage += decipher.final('utf-8');
    res.status(200).json({ decryptedMessage });
});

// Inicia o servidor
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
