const crypto = require("crypto");
require("dotenv").config();

const API_URL = "https://railroad-approve-august-base.trycloudflare.com/order";
// To Access Proxy server
const INTERNAL_SECRET = process.env.INTERNAL_SECRET;

async function sendSecureRequest() {
  try {
    const price = 1000000;

    const body = {
      quote: "KRW",
      target: "BTC",
      side: "BUY",
      price: price,
      qty: 0.01,
      postOnly: false
    };

    const timestamp = Date.now().toString();
    const payload = JSON.stringify(body) + timestamp;

    const signature = crypto
      .createHmac("sha256", INTERNAL_SECRET)
      .update(payload)
      .digest("hex");

    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "home-server", // ID 용도
        "x-timestamp": timestamp,
        "x-signature": signature
      },
      body: JSON.stringify(body)
    });

    const data = await response.json();
    console.log(data);

  } catch (err) {
    console.error(err);
  }
}

sendSecureRequest();
