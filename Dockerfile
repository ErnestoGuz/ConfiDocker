FROM node:18-alpine

WORKDIR /server

COPY package*.json ./

RUN npm install    # Se compila bcrypt dentro de Linux (correcto)

COPY . .

EXPOSE 5030

CMD ["node", "server.js"]

