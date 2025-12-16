FROM node:20-alpine AS base
WORKDIR /usr/src/app

FROM base AS deps
COPY package*.json ./
RUN npm ci

FROM deps AS build
COPY tsconfig*.json nest-cli.json ./
COPY src ./src
COPY prisma ./prisma
RUN npm run build

FROM node:20-alpine AS prod
WORKDIR /usr/src/app

ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=build /usr/src/app/dist ./dist
COPY prisma ./prisma

EXPOSE 3000

CMD ["node", "dist/main.js"]