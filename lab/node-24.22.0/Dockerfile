FROM node:22-bookworm-slim

WORKDIR /app
COPY package.json ./
COPY server.js ./

ENV PROFILE_NAME="node-24.22.0"
ENV SIM_NODE_VER="v24.22.0"
ENV SIM_BROTLI_VER="1.1.0"
ENV PORT=3000

EXPOSE 3000
CMD ["node", "server.js"]
