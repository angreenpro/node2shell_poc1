FROM node:22-bookworm-slim

WORKDIR /app
COPY package.json ./
COPY server.js ./

ENV PROFILE_NAME="node-24.22.2"
ENV SIM_NODE_VER="v24.22.2"
ENV SIM_BROTLI_VER="1.2.1"
ENV PORT=3000

EXPOSE 3000
CMD ["node", "server.js"]
