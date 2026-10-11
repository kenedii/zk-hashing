# Serves the static site in web/ (overview page, lab, Wasm verifier, published proofs).
# Build from the repository root:  docker build -f deploy/Dockerfile .
FROM nginx:1.27-alpine

COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY web/ /usr/share/nginx/html/

EXPOSE 8080
