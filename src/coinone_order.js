import express from 'express';
import axios from 'axios';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

// .env 설정 로드
dotenv.config();

// 3000번 서버와 반드시 동일해야 함!
const JWT_SECRET = process.env.JWT_SECRET; 
const ACCESS_TOKEN = process.env.COINONE_ACCESS_KEY;
const SECRET_KEY = process.env.COINONE_SECRET;

const app = express();
app.use(cors()); 
app.use(express.json());


// News data analyst가 일단 accessToken, quote, target, side, price, qty, postOnly
// 이 구성으로 /api/order/limit-buy/ 에 post 요청
// 



// [미들웨어] 3000번 서버에서 발급한 토큰이 유효한지 검사
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1]; // "Bearer [TOKEN]"

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: "토큰이 유효하지 않습니다. 다시 로그인하세요." });
            }
            req.user = user; // 토큰 속 유저 정보를 다음 단계로 넘김
            next();
        });
    } else {
        res.status(401).json({ message: "인증 토큰이 없습니다." });
    }
};

// 1. 주문 객체 생성 함수 (생략되지 않게 유지)
function createLimitOrder(accessToken, quote, target, side, price, qty, postOnly) {
  return {
    access_token: accessToken,
    nonce: uuidv4(),
    quote_currency: quote,
    target_currency: target,
    type: 'LIMIT',
    side: side,
    price: price,
    qty: qty,
    post_only: postOnly
  };
}

// 2. 보호된 주문 API (authenticateJWT 미들웨어 적용)
app.post('/api/order/limit-buy', authenticateJWT, async (req, res) => {
    console.log(`인증 성공! 요청 유저: ${req.user.email}`);

    const { price, qty } = req.body;
    if (!price || !qty) return res.status(400).json({ error: "필드 부족" });

    const payload = createLimitOrder(ACCESS_TOKEN, 'KRW', 'BTC', 'BUY', price, qty, false);

    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    const signature = crypto
        .createHmac('sha512', SECRET_KEY.toUpperCase())
        .update(encodedPayload)
        .digest('hex');

    try {
        const response = await axios.post('https://api.coinone.co.kr/v2.1/order', payload, {
            headers: {
                'Content-Type': 'application/json',
                'X-COINONE-PAYLOAD': encodedPayload,
                'X-COINONE-SIGNATURE': signature,
            }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json(error.response ? error.response.data : error.message);
    }
});


// 2-2. 미들웨어
const authenticateInternal = (req, res, next) => {
  const key = req.headers['x-api-key'];
  if (key !== process.env.INTERNAL_SECRET) {
    return res.status(401).json({ message: 'Invalid key' });
  }
  next();
};


// 2-2. 보호된 주문 API 자동화 프로그램용엑세스 미들웨어 authenticateInternal로 변경, quote, target, side, price, qty, postOnly 다 채워서 보내기
app.post('/api/order/limit-buy/advanced', authenticateInternal, async (req, res) => {
    console.log(`인증 성공! 요청 유저: ${req.user.email}`);

    const { quote, target, side, price, qty, postOnly} = req.body;
    if (!quote || !target || !side || !price || !qty || !postOnly) return res.status(400).json({ error: "필드 부족" });

    const payload = createLimitOrder(ACCESS_TOKEN, quote, target, side, price, qty, postOnly);

    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    const signature = crypto
        .createHmac('sha512', SECRET_KEY.toUpperCase())
        .update(encodedPayload)
        .digest('hex');

    try {
        const response = await axios.post('https://api.coinone.co.kr/v2.1/order', payload, {
            headers: {
                'Content-Type': 'application/json',
                'X-COINONE-PAYLOAD': encodedPayload,
                'X-COINONE-SIGNATURE': signature,
            }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json(error.response ? error.response.data : error.message);
    }
});

// n8n용 request API
// n8n 시그널 수신용 (POST)
// N8N_SECRET 필요!!
app.post('/api/signal', async (req, res) => {
    const { side, price, qty, signal_key } = req.body;
    if (!price || !qty) return res.status(400).json({ error: "필드 부족" });
    
    console.log(`n8n 요청 들어옴!`);

    // n8n 전용 보안키 확인 (TOTP 대신 사용)
    if (signal_key !== process.env.N8N_SECRET) return res.sendStatus(401);

    const payload = createLimitOrder(ACCESS_TOKEN, 'KRW', 'BTC', 'BUY', price, qty, false);

    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    const signature = crypto
        .createHmac('sha512', SECRET_KEY.toUpperCase())
        .update(encodedPayload)
        .digest('hex');

    try {
        const response = await axios.post('https://api.coinone.co.kr/v2.1/order', payload, {
            headers: {
                'Content-Type': 'application/json',
                'X-COINONE-PAYLOAD': encodedPayload,
                'X-COINONE-SIGNATURE': signature,
            }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json(error.response ? error.response.data : error.message);
    }
});

// 시세를 대신 가져와주는 프록시 API
app.get('/api/ticker', async (req, res) => {
    try {
        const response = await axios.get('https://api.coinone.co.kr/public/v2/ticker_new/KRW/BTC');
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: "시세 정보를 가져오지 못했습니다." });
    }
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
    console.log('🚀 Coinone Secure Proxy on http://localhost:4000');
});