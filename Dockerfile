# Clover — единый контейнер: сервис + PostgreSQL (DATABASE_URL в env)
FROM node:22-slim

WORKDIR /app

# Зависимости. better-sqlite3 — optionalDependencies (нужен только для локалки
# без DATABASE_URL): в контейнере не ставится, нативная сборка не требуется
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --omit=optional && npm cache clean --force

# Код и бинарь сканера
COPY server.js ./
COPY backend ./backend
COPY frontend ./frontend
COPY scripts ./scripts
COPY clover.exe ./

ENV PORT=3000 \
    CLOVER_EXE_PATH=/app/clover.exe
EXPOSE 3000

CMD ["node", "server.js"]
