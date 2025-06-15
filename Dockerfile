FROM mcr.microsoft.com/playwright:v1.53.0-jammy

WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3001
CMD ["node", "index.js"]
