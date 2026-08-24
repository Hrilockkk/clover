# Clover — единый контейнер: сервис + SQLite (в named volume)
FROM node:22-slim

WORKDIR /app

# Инструменты сборки: если prebuild better-sqlite3 не скачается (таймаут сети),
# node-gyp соберёт его из исходников
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

# Зависимости
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Код и бинарь сканера
COPY server.js ./
COPY backend ./backend
COPY frontend ./frontend
COPY scripts ./scripts
COPY clover.exe ./

# База живёт в /app/data — монтируется volume'ом и переживает пересборку
ENV PORT=3000 \
    CLOVER_EXE_PATH=/app/clover.exe
EXPOSE 3000
VOLUME ["/app/data"]

CMD ["node", "server.js"]
