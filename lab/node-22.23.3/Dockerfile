FROM node:22-bookworm-slim

WORKDIR /app
COPY package.json ./
COPY server.js ./

ENV PROFILE_NAME="node-22.23.3"
ENV SIM_NODE_VER="v22.23.3"
ENV SIM_BROTLI_VER="1.1.0"
ENV PORT=3000

EXPOSE 3000
CMD ["node", "server.js"]
