FROM node:24-alpine AS builder
WORKDIR /usr/src/app

ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL

COPY package*.json ./
RUN npm ci

COPY tsconfig*.json nest-cli.json prisma.config.ts ./
COPY src ./src
COPY prisma ./prisma

RUN npx prisma generate
RUN npm run build

FROM node:24-alpine AS prod
WORKDIR /usr/src/app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /usr/src/app/dist ./dist
COPY --from=builder /usr/src/app/node_modules ./node_modules

COPY prisma ./prisma
COPY prisma.config.ts ./

EXPOSE 8080

CMD ["node", "dist/src/main.js"]
