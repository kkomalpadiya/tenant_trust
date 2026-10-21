ARG FABRIC_CHAINCODE_NODE_IMAGE=node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94
FROM ${FABRIC_CHAINCODE_NODE_IMAGE} AS build

WORKDIR /opt/tenant-trust/audit-chaincode
COPY chaincode/audit/package.json chaincode/audit/package-lock.json ./
RUN npm ci --ignore-scripts
COPY chaincode/audit/tsconfig.json ./
COPY chaincode/audit/src ./src
RUN npm run build && npm prune --omit=dev

FROM ${FABRIC_CHAINCODE_NODE_IMAGE}
ENV NODE_ENV=production
WORKDIR /opt/tenant-trust/audit-chaincode
COPY --from=build --chown=node:node /opt/tenant-trust/audit-chaincode/package.json ./
COPY --from=build --chown=node:node /opt/tenant-trust/audit-chaincode/node_modules ./node_modules
COPY --from=build --chown=node:node /opt/tenant-trust/audit-chaincode/dist ./dist
USER node
EXPOSE 9999
CMD ["npm", "start"]
