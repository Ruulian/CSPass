PORT=8080
docker build -t cspass .
docker run -p $PORT:$PORT cspass # Doesn't launch in background