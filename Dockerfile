FROM node:20-alpine AS base
WORKDIR /usr/src/app

FROM base AS deps
ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL
COPY package*.json ./
RUN npm ci

FROM deps AS build
ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL
COPY tsconfig*.json nest-cli.json prisma.config.ts ./
COPY src ./src
COPY prisma ./prisma

RUN npx prisma generate

RUN npm run build

FROM node:20-alpine AS prod
WORKDIR /usr/src/app
ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL

ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=build /usr/src/app/dist ./dist
COPY prisma ./prisma
COPY prisma.config.ts ./

RUN npx prisma generate

EXPOSE 3000

CMD ["node", "dist/main.js"]