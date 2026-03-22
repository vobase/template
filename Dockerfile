FROM oven/bun:1.3.10-slim AS base
WORKDIR /app

# Install all deps (including devDeps for Vite build)
FROM base AS build
COPY package.json bun.lock* ./
COPY patches/ ./patches/
RUN bun install --frozen-lockfile
COPY . .
RUN bun run build

# Production deps only
FROM base AS prod-deps
COPY package.json bun.lock* ./
COPY patches/ ./patches/
RUN bun install --frozen-lockfile --production

# Final image
FROM base
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY . .
EXPOSE 3000
CMD ["bun", "run", "server.ts"]
