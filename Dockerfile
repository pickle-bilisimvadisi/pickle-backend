FROM node:24-alpine AS builder
WORKDIR /usr/src/app
ENV NODE_ENV=production

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

COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/dist ./dist
COPY prisma ./prisma
COPY prisma.config.ts ./

EXPOSE 3000
CMD ["node", "dist/main.js"]
