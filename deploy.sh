curl -o init.sql https://raw.githubusercontent.com/SAM-Research/sam-instant-messenger/refs/heads/main/server/database/init.sql
mv ./init.sql ./initdb/init.sql

docker compose up