FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY packages ./packages
RUN npm install --omit=dev --package-lock=false && npm run build --workspace @dsh-docker-services/shared && npm run build --workspace @dsh-docker-services/controller
USER node
ENTRYPOINT ["node", "packages/controller/lib/src/main.js"]
