FROM node:20.19.5-bookworm-slim

WORKDIR /app
COPY package.json ./
COPY server.js ./

ENV PROFILE_NAME="node-20.19.5"
ENV SIM_NODE_VER="v20.19.5"
ENV SIM_BROTLI_VER="1.0.9"
ENV PORT=3000

EXPOSE 3000
CMD ["node", "server.js"]
