PORT=6379
HOST="128.105.144.101"

if [ "$2" ];
then 
	HOST=$2
fi

if [ "$3" ];
then
        PORT=$3
fi

if [ $1 = "load" ];
then
	./bin/ycsb load redis -s -P workloads/workload_m_load -p "redis.host=$HOST" -p "redis.port=$PORT" -p "redis.consumer_host=127.0.0.1" -p "redis.consumer_port=6379"
elif [ $1 = "run" ];
then
	/bin/ycsb run redis -s -P workloads/workload_m_run -p "redis.host=$HOST" -p "redis.port=$PORT" -p "status.interval=1"
fi
