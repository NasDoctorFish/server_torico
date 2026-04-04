"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", { value: true });
var express_1 = require("express");
var axios_1 = require("axios");
var dotenv_1 = require("dotenv");
var jsonwebtoken_1 = require("jsonwebtoken");
var QRCode = require("qrcode");
var otplib_1 = require("otplib");
var node_crypto_1 = require("node:crypto");
var node_path_1 = require("node:path");
var node_url_1 = require("node:url");
dotenv_1.default.config();
if (!globalThis.crypto) {
    globalThis.crypto = node_crypto_1.webcrypto;
}
var PORT = Number((_a = process.env.PORT) !== null && _a !== void 0 ? _a : 4000);
var JWT_SECRET = (_b = process.env.JWT_SECRET) !== null && _b !== void 0 ? _b : '';
var ACCESS_TOKEN = (_c = process.env.ACCESS_TOKEN) !== null && _c !== void 0 ? _c : '';
var SECRET_KEY = (_d = process.env.SECRET_KEY) !== null && _d !== void 0 ? _d : '';
var SIGNAL_API_KEY = (_e = process.env.SIGNAL_API_KEY) !== null && _e !== void 0 ? _e : '';
if (!JWT_SECRET) {
    throw new Error('환경변수 JWT_SECRET가 없습니다.');
}
var __filename = (0, node_url_1.fileURLToPath)(import.meta.url);
var __dirname = node_path_1.default.dirname(__filename);
var staticDir = node_path_1.default.join(__dirname, process.env.NODE_ENV === 'production' ? '../src' : '.');
var app = (0, express_1.default)();
var users = [
    { id: 1, name: 'LEE JUWON', role: 'admin', email: 'juwonlee3465@gmail.com' }
];
var issueAccessToken = function (user) {
    return jsonwebtoken_1.default.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, {
        expiresIn: '5m'
    });
};
var authenticateJWT = function (req, res, next) {
    var _a;
    var authHeader = (_a = req.headers.authorization) !== null && _a !== void 0 ? _a : '';
    var token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) {
        return res.status(401).json({ success: false, message: 'JWT 토큰이 필요합니다.' });
    }
    try {
        jsonwebtoken_1.default.verify(token, JWT_SECRET);
        return next();
    }
    catch (error) {
        return res.status(401).json({ success: false, message: 'JWT 인증 실패' });
    }
};
var authorizeSignal = function (req, res, next) {
    var _a;
    var apiKey = req.headers['x-api-key'];
    var authHeader = (_a = req.headers.authorization) !== null && _a !== void 0 ? _a : '';
    var bearerToken = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7) : '';
    if (SIGNAL_API_KEY && apiKey === SIGNAL_API_KEY) {
        return next();
    }
    if (!bearerToken) {
        return res.status(401).json({ success: false, message: 'Signal 인증이 필요합니다.' });
    }
    try {
        jsonwebtoken_1.default.verify(bearerToken, JWT_SECRET);
        return next();
    }
    catch (error) {
        return res.status(401).json({ success: false, message: 'Signal JWT 인증 실패' });
    }
};
var normalizeOrder = function (payload) {
    var _a, _b;
    var targetCurrency = (_a = payload.targetCurrency) !== null && _a !== void 0 ? _a : 'BTC';
    var quoteCurrency = (_b = payload.quoteCurrency) !== null && _b !== void 0 ? _b : 'KRW';
    if (!payload.side || !payload.type || !payload.qty) {
        throw new Error('주문 필수 값이 없습니다.');
    }
    if (payload.type !== 'MARKET' && !payload.price) {
        throw new Error('LIMIT 또는 STOP_LIMIT 주문은 price가 필요합니다.');
    }
    if (payload.type === 'STOP_LIMIT' && !payload.triggerPrice) {
        throw new Error('STOP_LIMIT 주문은 triggerPrice가 필요합니다.');
    }
    return __assign(__assign({}, payload), { targetCurrency: targetCurrency, quoteCurrency: quoteCurrency });
};
var CoinoneClient = /** @class */ (function () {
    function CoinoneClient(accessToken, secretKey) {
        this.http = axios_1.default.create({
            baseURL: 'https://api.coinone.co.kr',
            timeout: 15000
        });
        this.accessToken = accessToken;
        this.secretKey = secretKey;
    }
    CoinoneClient.prototype.signPayload = function (payload) {
        var raw = JSON.stringify(payload);
        var base64Payload = Buffer.from(raw).toString('base64');
        var signature = node_crypto_1.default.createHmac('sha512', this.secretKey).update(base64Payload).digest('hex');
        return {
            'X-COINONE-PAYLOAD': base64Payload,
            'X-COINONE-SIGNATURE': signature
        };
    };
    CoinoneClient.prototype.postPrivate = function (endpoint, payload) {
        return __awaiter(this, void 0, void 0, function () {
            var body, headers, response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        body = __assign(__assign({}, payload), { access_token: this.accessToken, nonce: Date.now().toString() });
                        headers = this.signPayload(body);
                        return [4 /*yield*/, this.http.post(endpoint, body, {
                                headers: __assign({ 'Content-Type': 'application/json' }, headers)
                            })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, response.data];
                }
            });
        });
    };
    CoinoneClient.prototype.placeOrder = function (order) {
        return __awaiter(this, void 0, void 0, function () {
            var normalized, payload;
            return __generator(this, function (_a) {
                normalized = normalizeOrder(order);
                payload = {
                    side: normalized.side,
                    type: normalized.type,
                    price: normalized.type === 'MARKET' ? undefined : normalized.price,
                    qty: normalized.qty,
                    trigger_price: normalized.type === 'STOP_LIMIT' ? normalized.triggerPrice : undefined,
                    target_currency: normalized.targetCurrency,
                    quote_currency: normalized.quoteCurrency
                };
                Object.keys(payload).forEach(function (key) {
                    if (payload[key] === undefined) {
                        delete payload[key];
                    }
                });
                return [2 /*return*/, this.postPrivate('/v2.1/order', payload)];
            });
        });
    };
    return CoinoneClient;
}());
var coinoneClient = ACCESS_TOKEN && SECRET_KEY ? new CoinoneClient(ACCESS_TOKEN, SECRET_KEY) : null;
app.use(express_1.default.json({ limit: '1mb' }));
app.use(express_1.default.urlencoded({ extended: true }));
app.use(function (req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-KEY');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    return next();
});
app.use(express_1.default.static(staticDir));
app.get('/', function (req, res) {
    res.sendFile(node_path_1.default.join(staticDir, 'index.html'));
});
app.get('/api/users/:id/setup-otp', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var user, secret, otpauth, qrImageUrl;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                user = users.find(function (entry) { return entry.id === Number(req.params.id); });
                if (!user) {
                    return [2 /*return*/, res.status(404).json({ success: false, message: '유저 없음' })];
                }
                secret = (0, otplib_1.generateSecret)();
                user.otpSecret = secret;
                otpauth = (0, otplib_1.generateURI)({
                    issuer: 'Coinone Home Server',
                    label: user.email,
                    secret: secret
                });
                return [4 /*yield*/, QRCode.toDataURL(otpauth)];
            case 1:
                qrImageUrl = _a.sent();
                return [2 /*return*/, res.json({
                        success: true,
                        secret: secret,
                        qrCode: qrImageUrl
                    })];
        }
    });
}); });
app.post('/api/verify-otp', function (req, res) {
    var _a = req.body, userId = _a.userId, token = _a.token;
    var user = users.find(function (entry) { return entry.id === Number(userId); });
    if (!user || !user.otpSecret) {
        return res.status(400).json({ success: false, message: 'OTP 설정이 필요합니다.' });
    }
    var isValid = (0, otplib_1.verifySync)({ token: token, secret: user.otpSecret });
    if (!isValid) {
        return res.status(401).json({ success: false, message: '번호가 틀렸습니다.' });
    }
    return res.json({
        success: true,
        message: '인증 성공!',
        accessToken: issueAccessToken(user)
    });
});
app.get('/api/ticker', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var response, error_1;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, axios_1.default.get('https://api.coinone.co.kr/public/v2/ticker_new/KRW/BTC')];
            case 1:
                response = _a.sent();
                return [2 /*return*/, res.json(response.data)];
            case 2:
                error_1 = _a.sent();
                return [2 /*return*/, res.status(502).json({
                        success: false,
                        message: '티커 프록시 실패',
                        error: error_1.message
                    })];
            case 3: return [2 /*return*/];
        }
    });
}); });
app.post('/api/order', authenticateJWT, function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var result, error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                if (!coinoneClient) {
                    return [2 /*return*/, res.status(500).json({
                            success: false,
                            message: 'ACCESS_TOKEN 또는 SECRET_KEY가 없습니다.'
                        })];
                }
                _a.label = 1;
            case 1:
                _a.trys.push([1, 3, , 4]);
                return [4 /*yield*/, coinoneClient.placeOrder(req.body)];
            case 2:
                result = _a.sent();
                return [2 /*return*/, res.json({ success: true, data: result })];
            case 3:
                error_2 = _a.sent();
                return [2 /*return*/, res.status(400).json({
                        success: false,
                        message: error_2.message
                    })];
            case 4: return [2 /*return*/];
        }
    });
}); });
app.post('/api/signal', authorizeSignal, function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var result, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                if (!coinoneClient) {
                    return [2 /*return*/, res.status(500).json({
                            success: false,
                            message: 'ACCESS_TOKEN 또는 SECRET_KEY가 없습니다.'
                        })];
                }
                _a.label = 1;
            case 1:
                _a.trys.push([1, 3, , 4]);
                return [4 /*yield*/, coinoneClient.placeOrder(req.body)];
            case 2:
                result = _a.sent();
                return [2 /*return*/, res.json({ success: true, data: result })];
            case 3:
                error_3 = _a.sent();
                return [2 /*return*/, res.status(400).json({
                        success: false,
                        message: error_3.message
                    })];
            case 4: return [2 /*return*/];
        }
    });
}); });
app.use(function (req, res) {
    res.status(404).json({ success: false, message: '요청한 리소스를 찾을 수 없습니다.' });
});
app.use(function (err, req, res, next) {
    console.error(err.stack);
    res.status(500).json({ success: false, message: '서버 에러가 발생했습니다', error: err.message });
});
app.listen(PORT, function () {
    console.log("\uD83D\uDE80 Coinone Home Server running at http://localhost:".concat(PORT));
});
