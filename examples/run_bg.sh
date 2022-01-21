PORT=8080
docker build -t cspass .
docker run -d -p $PORT:$PORT cspass