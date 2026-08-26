FROM docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d AS dockercli
FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build
WORKDIR /app
RUN npm install --global npm@11.12.1 --ignore-scripts
COPY package.json package-lock.json tsconfig.json ./
COPY packages ./packages
RUN npm ci --ignore-scripts && npm run build

FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS runtime
WORKDIR /app
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/shared/package.json ./packages/shared/package.json
COPY --from=build /app/packages/shared/lib ./packages/shared/lib
COPY --from=build /app/packages/controller/package.json ./packages/controller/package.json
COPY --from=build /app/packages/controller/lib ./packages/controller/lib
RUN mkdir -p /run/dsh-docker-services /var/lib/dsh-docker-services /var/lib/dsh-audit-checkpoint && chown -R node:node /run/dsh-docker-services /var/lib/dsh-docker-services /var/lib/dsh-audit-checkpoint
USER node
ENTRYPOINT ["node", "packages/controller/lib/src/main.js"]
CMD ["/etc/dsh-docker-services/controller.json"]
