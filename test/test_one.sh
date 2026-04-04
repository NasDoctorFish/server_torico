# 1. 서버 실행 (proxy)
npx tsx src/server.ts

# 2. 서버 살아있는지 확인
curl http://localhost:4000

# 3. 테스트 요청 (토큰 + 최소금액 충족)
curl -X POST http://localhost:4000/api/signal \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer 실제토큰" \
  -d '{"symbol":"BTC","price":50000000,"qty":0.001,"side":"buy"}'

# 4. JS 테스트 (node-fetch 필요 없음)
node test/order_test.cjs