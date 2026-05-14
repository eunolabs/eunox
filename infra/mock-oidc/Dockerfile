FROM node:18-alpine

WORKDIR /app

# No npm dependencies — uses Node.js built-in Web Crypto API only.
COPY server.mjs ./

EXPOSE 3003

CMD ["node", "server.mjs"]
