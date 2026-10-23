# MAESTRO - server setup

Users sign up, buy credits through Epoint and render with YOUR OpenAI key (kept on the server).

1. Install Node 18+ then: `npm install`
2. `cp .env.example .env` and fill in OPENAI_API_KEY, JWT_SECRET, BASE_URL and the EPOINT_* keys
3. Epoint: in your Epoint cabinet the callback (result_url) is sent automatically with each payment:
   `BASE_URL/api/epoint-callback` - BASE_URL must be a public https address that Epoint can reach
4. `npm start` -> open http://localhost:3000
5. Deploy to a Node host with a persistent disk (Render, Railway, Fly.io, VPS). Keep the `data/` folder (SQLite + images).

Credits are granted ONLY when Epoint's signed callback arrives (signature, order and amount are checked).
