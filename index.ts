import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { Pool } from 'pg';
import path from 'path';

dotenv.config();

const app = express();
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const externalUrl = process.env.RENDER_EXTERNAL_URL;
const PORT = externalUrl && process.env.PORT ? parseInt(process.env.PORT) : 3000;

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012'; 
const IV_LENGTH = 16;

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',	
    database: process.env.DB_NAME || 'web2_security',
    password: process.env.DB_PASSWORD || 'password',
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

app.get('/', (req: Request, res: Response) => {
  res.render('index');
});

app.get('/sensitive-data-exposure', (req: Request, res: Response) => {
  res.render('sensitive_data_exposure', { savedData: null });
});

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
      res.render('sensitive_data_exposure', { savedData: result.rows[0] }); // Send back data to the client in a format same as it is in the database
    } catch (error) {
      res.status(500).send('Error saving data');
    }
  });

  //We use this function to sanitize the input and prevent XSS attacks
  function sanitizeInput(input: string): string {
    // Map of characters to their HTML entity equivalents
    const escapeChars: { [key: string]: string } = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;'
    };
  
    return input.replace(/[&<>"']/g, (match: string): string => escapeChars[match]);
  }
  
  app.get('/xss', (req, res) => {
    const { input, enableXss } = req.query;
    let output = input;
  
    if (enableXss !== 'true' && input) {
      output = sanitizeInput(input as string);
    }
  
    res.render('xss', { output });
  });

  const hostname = '0.0.0.0';
  app.listen(PORT, hostname, () => {
  console.log(`Server locally running at http://${hostname}:${PORT}/ and from
  outside on ${externalUrl}`);
  });