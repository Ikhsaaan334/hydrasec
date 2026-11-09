FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

# docker-cli klien tidak dibutuhkan — worker memakai Docker Engine API via socket.
# Worker berjalan sebagai root: ia memegang docker.sock (setara root host) dan
# perlu chown direktori output per-scan untuk isolasi uid antar-kontainer tool.
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY src ./src

CMD ["node", "src/index.js"]
