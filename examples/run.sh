PORT=8080
docker build -t sql-basics-1 .
docker run -d -p $PORT:$PORT sql-basics-1