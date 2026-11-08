# UniGame Hub — Cloud Run image. Node 24 runs the TypeScript sources directly (type stripping).
FROM node:24.11.1-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY src ./src
COPY sdk ./sdk
COPY config ./config
USER node
ENV PORT=8080
EXPOSE 8080
CMD ["node", "src/server.ts"]
