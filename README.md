# Description
Server Torico is a Coin trading backend server consist of coinorder server and proxy server. The coin trade uses CoinOne(코인원) Platform based on South Korea using REST API.

> [coinone_order.js] -> [server.ts(proxy)] -> [Coinone API]

coinone_order.js -> port 3000
Proxy server: port 4000

Coinone_order sends the order request to proxy server, then proxy sends the request to Coinone API. Using proxy server allows API request in more secured environment by controling the API KEY exposure and avoid direct exposure to any attack caused during the transaction.

# Quick start
1. Install server_torico
```
git clone
cd server_torico
npm install
```
2. Set .env under server_torico
```
# Example
PORT=4000 #proxy server port
COINONE_API_KEY=your_api_key
COINONE_SECRET_KEY=your_secret_key
INTERNAL_SECRET=your_internal_secret
```
2. Go to src folder
3. Run server.ts (proxy server first)
```npx tsx src/server.ts```
4. Run coinone_order.js in new terminal
```node coinone_order.js```
5. Check the port status
```curl http://localhost:<PORT_NUMBER_HERE>```
# Reference
[Coinone Documentation](https://docs.coinone.co.kr/reference/range-unit
)
