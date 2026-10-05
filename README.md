# TRUST-PASS

TRUST-PASS is a small clinical-data trust layer prototype. It sits between systems that exchange healthcare data and the applications that consume it, checking whether an exchange is authentic, intact, fresh, authorized, and safe to use.

The project includes a dashboard and an API. The dashboard makes the trust decisions easy to explore; the API performs the verification and keeps the exchange, audit, and Trust Pass records.

## What you can try

The **Demo Lab** in the dashboard runs synthetic exchanges through the backend verification flow. Try a clean exchange, then compare it with cases such as:

- tampered payloads
- replay attacks
- expired exchanges
- unknown sources
- unauthorized transformations
- context mismatches

Depending on the result, an exchange is allowed, sent for review, or quarantined. An allowed exchange can receive a signed **Trust Pass**, which a downstream consumer can verify before using the data.

## How it fits together

```text
React dashboard  →  Express API  →  MongoDB
                         │
                         ├─ source registry
                         ├─ exchange verification
                         ├─ trust scoring and policy
                         ├─ audit trail
                         └─ signed Trust Passes
```

- `client/` — React 19 + TypeScript + Vite dashboard
- `server/` — Express 5 + TypeScript API, backed by MongoDB
- `server/tests/` — API and verification tests

## Requirements

- Node.js 20 or newer
- npm
- MongoDB running locally, or a reachable MongoDB instance

## Run it locally

1. Install dependencies:

   ```bash
   cd server && npm install
   cd ../client && npm install
   ```

2. Configure the API:

   ```bash
   cd server
   cp .env.example .env
   ```

   The defaults expect MongoDB at `mongodb://127.0.0.1:27017/trust_pass` and the dashboard at `http://localhost:5173`.

3. Generate the local demo keys and seed the source registry:

   ```bash
   cd server
   npm run keys:generate
   npm run seed:demo
   ```

4. Start the API in one terminal:

   ```bash
   cd server
   npm run dev
   ```

5. Start the dashboard in another terminal:

   ```bash
   cd client
   npm run dev
   ```

Open the local URL printed by Vite, usually `http://localhost:5173`.

If the API is running somewhere else, set `VITE_API_BASE_URL` before starting the client. It should point to the API base, for example `http://localhost:4000/api/v1`.

## Useful commands

Run these from the relevant directory:

```bash
# client
npm run build
npm run lint

# server
npm run build
npm run lint
npm test
```

The API health endpoint is available at `GET /api/v1/health`.

## A note about the prototype

This is a demonstration and development project, not a production clinical-data system. The bundled keys, seeded records, synthetic payloads, and local defaults are intended for testing the trust flow only. Before using an approach like this in a real environment, add production key management, identity and access controls, operational monitoring, durable audit storage, privacy safeguards, and a thorough compliance review.

## License

See [LICENSE](LICENSE).
