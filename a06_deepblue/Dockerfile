# Step 1: Build React App
FROM node:18
ENV TERM=xterm-256color

# Step 2: Setup Express Server
WORKDIR /app
COPY server_for_player ./server
WORKDIR /app/server
RUN apt-get update -y && apt-get install -y python3 python3-pip build-essential ncurses-term
RUN python3 -m pip install --break-system-packages python-chess
RUN python3 -m pip install --break-system-packages pwntools
RUN npm install
RUN npm install express body-parser
RUN npm install cors

# Expose port and start application
EXPOSE 4000
CMD ["node", "server.cjs"]
