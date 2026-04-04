import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import axios from 'axios';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import * as QRCode from 'qrcode';
import { generateSecret, generateURI, verifySync } from 'otplib';
import crypto, { webcrypto } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as unknown as Crypto;
}

const PORT = Number(process.env.PORT ?? 4000);
const JWT_SECRET = process.env.JWT_SECRET ?? '';
const ACCESS_TOKEN = process.env.ACCESS_TOKEN ?? '';
const SECRET_KEY = process.env.SECRET_KEY ?? '';
const SIGNAL_API_KEY = process.env.SIGNAL_API_KEY ?? '';

if (!JWT_SECRET) {
  throw new Error('환경변수 JWT_SECRET가 없습니다.');
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const staticDir = path.join(__dirname, process.env.NODE_ENV === 'production' ? '../src' : '.');

const app = express();

interface User {
  id: number;
  email: string;
  name: string;
  role: 'admin' | 'user';
  otpSecret?: string;
}

interface JwtPayload {
  id: number;
  email: string;
  role: User['role'];
}

type OrderSide = 'BUY' | 'SELL';
type OrderType = 'LIMIT' | 'MARKET' | 'STOP_LIMIT';

interface OrderRequest {
  side: OrderSide;
  type: OrderType;
  price?: number;
  qty: number;
  triggerPrice?: number;
  targetCurrency?: string;
  quoteCurrency?: string;
}

const users: User[] = [
  { id: 1, name: 'LEE JUWON', role: 'admin', email: 'juwonlee3465@gmail.com' }
];

const issueAccessToken = (user: User) => {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, {
    expiresIn: '5m'
  });
};

const authenticateJWT = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization ?? '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

  if (!token) {
    return res.status(401).json({ success: false, message: 'JWT 토큰이 필요합니다.' });
  }

  try {
    jwt.verify(token, JWT_SECRET) as JwtPayload;
    return next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'JWT 인증 실패' });
  }
};

const authorizeSignal = (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'];
  const authHeader = req.headers.authorization ?? '';
  const bearerToken = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7) : '';

  if (SIGNAL_API_KEY && apiKey === SIGNAL_API_KEY) {
    return next();
  }

  if (!bearerToken) {
    return res.status(401).json({ success: false, message: 'Signal 인증이 필요합니다.' });
  }

  try {
    jwt.verify(bearerToken, JWT_SECRET) as JwtPayload;
    return next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Signal JWT 인증 실패' });
  }
};

const normalizeOrder = (payload: OrderRequest) => {
  const targetCurrency = payload.targetCurrency ?? 'BTC';
  const quoteCurrency = payload.quoteCurrency ?? 'KRW';

  if (!payload.side || !payload.type || !payload.qty) {
    throw new Error('주문 필수 값이 없습니다.');
  }

  if (payload.type !== 'MARKET' && !payload.price) {
    throw new Error('LIMIT 또는 STOP_LIMIT 주문은 price가 필요합니다.');
  }

  if (payload.type === 'STOP_LIMIT' && !payload.triggerPrice) {
    throw new Error('STOP_LIMIT 주문은 triggerPrice가 필요합니다.');
  }

  return {
    ...payload,
    targetCurrency,
    quoteCurrency
  };
};

class CoinoneClient {
  private readonly accessToken: string;
  private readonly secretKey: string;
  private readonly http = axios.create({
    baseURL: 'https://api.coinone.co.kr',
    timeout: 15000
  });

  constructor(accessToken: string, secretKey: string) {
    this.accessToken = accessToken;
    this.secretKey = secretKey;
  }

  private signPayload(payload: Record<string, unknown>) {
    const raw = JSON.stringify(payload);
    const base64Payload = Buffer.from(raw).toString('base64');
    const signature = crypto.createHmac('sha512', this.secretKey).update(base64Payload).digest('hex');

    return {
      'X-COINONE-PAYLOAD': base64Payload,
      'X-COINONE-SIGNATURE': signature
    };
  }

  private async postPrivate<T>(endpoint: string, payload: Record<string, unknown>) {
    const body = {
      ...payload,
      access_token: this.accessToken,
      nonce: Date.now().toString()
    };

    const headers = this.signPayload(body);

    const response = await this.http.post<T>(endpoint, body, {
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    });

    return response.data;
  }

  async placeOrder(order: OrderRequest) {
    const normalized = normalizeOrder(order);
    const payload: Record<string, unknown> = {
      side: normalized.side,
      type: normalized.type,
      price: normalized.type === 'MARKET' ? undefined : normalized.price,
      qty: normalized.qty,
      trigger_price: normalized.type === 'STOP_LIMIT' ? normalized.triggerPrice : undefined,
      target_currency: normalized.targetCurrency,
      quote_currency: normalized.quoteCurrency
    };

    Object.keys(payload).forEach((key) => {
      if (payload[key] === undefined) {
        delete payload[key];
      }
    });

    return this.postPrivate('/v2.1/order', payload);
  }
}

const coinoneClient = ACCESS_TOKEN && SECRET_KEY ? new CoinoneClient(ACCESS_TOKEN, SECRET_KEY) : null;

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-KEY');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  return next();
});

app.use(express.static(staticDir));

app.get('/', (req: Request, res: Response) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

app.get('/api/users/:id/setup-otp', async (req: Request, res: Response) => {
  const user = users.find((entry) => entry.id === Number(req.params.id));
  if (!user) {
    return res.status(404).json({ success: false, message: '유저 없음' });
  }

  const secret = generateSecret();
  user.otpSecret = secret;

  const otpauth = generateURI({
    issuer: 'Coinone Home Server',
    label: user.email,
    secret
  });

  const qrImageUrl = await QRCode.toDataURL(otpauth);

  return res.json({
    success: true,
    secret,
    qrCode: qrImageUrl
  });
});

app.post('/api/verify-otp', (req: Request, res: Response) => {
  const { userId, token } = req.body as { userId: number; token: string };
  const user = users.find((entry) => entry.id === Number(userId));

  if (!user || !user.otpSecret) {
    return res.status(400).json({ success: false, message: 'OTP 설정이 필요합니다.' });
  }

  const isValid = verifySync({ token, secret: user.otpSecret });
  if (!isValid) {
    return res.status(401).json({ success: false, message: '번호가 틀렸습니다.' });
  }

  return res.json({
    success: true,
    message: '인증 성공!',
    accessToken: issueAccessToken(user)
  });
});

app.get('/api/ticker', async (req: Request, res: Response) => {
  try {
    const response = await axios.get('https://api.coinone.co.kr/public/v2/ticker_new/KRW/BTC');
    return res.json(response.data);
  } catch (error) {
    return res.status(502).json({
      success: false,
      message: '티커 프록시 실패',
      error: (error as Error).message
    });
  }
});

app.post('/api/order', authenticateJWT, async (req: Request, res: Response) => {
  if (!coinoneClient) {
    return res.status(500).json({
      success: false,
      message: 'ACCESS_TOKEN 또는 SECRET_KEY가 없습니다.'
    });
  }

  try {
    const result = await coinoneClient.placeOrder(req.body as OrderRequest);
    return res.json({ success: true, data: result });
  } catch (error) {
    console.log(res);
    return res.status(400).json({
      success: false,
      message: (error as Error).message
    });
  }
});

app.post('/api/signal', authorizeSignal, async (req: Request, res: Response) => {
  if (!coinoneClient) {
    return res.status(500).json({
      success: false,
      message: 'ACCESS_TOKEN 또는 SECRET_KEY가 없습니다.'
    });
  }

  try {
    const result = await coinoneClient.placeOrder(req.body as OrderRequest);
    return res.json({ success: true, data: result });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: (error as Error).message
    });
  }
});

app.use((req: Request, res: Response) => {
  res.status(404).json({ success: false, message: '요청한 리소스를 찾을 수 없습니다.' });
});

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.log("🔥 REQUEST HIT:", req.method, req.url);
  res.status(500).json({ success: false, message: '서버 에러가 발생했습니다', error: err.message });
});


app.listen(PORT, () => {
  console.log(`🚀 Coinone Home Server running at http://localhost:${PORT}`);
});
