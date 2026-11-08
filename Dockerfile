FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

# Render dynamically sets PORT (defaults to 10000)
ENV PORT=10000
EXPOSE 10000

CMD ["npm", "start"]
