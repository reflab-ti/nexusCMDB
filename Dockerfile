FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN apk add --no-cache tzdata && npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY server ./server
EXPOSE 3002
USER node
CMD ["node", "server/index.js"]
