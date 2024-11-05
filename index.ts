import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { Pool } from 'pg';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012'; 
const IV_LENGTH = 16;

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',	
    database: process.env.DB_NAME || 'web2_security',
    password: process.env.DB_PASSWORD || 'bazepodataka',
    port: Number(process.env.DB_PORT) || 5432,
  });

function encrypt(text: string): string {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}
  
/*function decrypt(text: string): string {
    const [iv, encryptedText] = text.split(':');
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      Buffer.from(ENCRYPTION_KEY),
      Buffer.from(iv, 'hex')
    );
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }*/

app.use(express.json());


app.post('/save-card', async (req: Request, res: Response) => {
    const { firstName, lastName, cardNumber, expiryDate, cvc } = req.body;
    const vulnerability = req.query.vulnerability === '1';
  
    const storedCardNumber = vulnerability ? cardNumber : encrypt(cardNumber);
    const storedCvc = vulnerability ? cvc : encrypt(cvc) ;
    const storedExpiryDate = vulnerability ? expiryDate : encrypt(expiryDate);
  
    try {
      const result = await pool.query(
        'INSERT INTO credit_cards (first_name, last_name, card_number, expiry_date, cvc) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [firstName, lastName, storedCardNumber, storedExpiryDate, storedCvc]
      );
      res.json(result.rows[0]); // Send back saved data as it appears in the database
    } catch (error) {
      res.status(500).send('Error saving data');
    }
  });

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});