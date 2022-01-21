PORT=8080
docker build -t cspass1 .
docker run -p $PORT:$PORT cspass1 # Doesn't launch in background