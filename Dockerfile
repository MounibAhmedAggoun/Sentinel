# syntax=docker/dockerfile:1

# Stage 1: install everything and build the CLI bundle.
FROM node:22-alpine AS build
WORKDIR /src
COPY . .
RUN npm ci
RUN npm run build --workspace cli
# The bundle already contains @sentinel/core and @sentinel/scanner, so the
# runtime only needs the CLI's third-party packages. Write a package.json
# with those, plus the CLI's version, because the CLI reads its version from
# the package.json next to its dist folder.
RUN mkdir /out && node --input-type=commonjs -e "const p=JSON.parse(require('fs').readFileSync('cli/package.json','utf8'));const d={...p.dependencies};delete d['@sentinel/core'];delete d['@sentinel/scanner'];require('fs').writeFileSync('/out/package.json',JSON.stringify({name:'sentinel-runtime',version:p.version,private:true,type:'module',dependencies:d}));"

# Stage 2: a small runtime image, running as a non-root user.
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /out/package.json ./package.json
RUN npm install --omit=dev && npm cache clean --force
COPY --from=build /src/cli/dist ./dist
USER node
ENTRYPOINT ["node", "dist/index.js"]
CMD ["--help"]