package redispool

import (
	"log"
	"time"

	"github.com/garyburd/redigo/redis"
)

var ConnPool *redis.Pool
var ConnPoolLocalNet *redis.Pool // 访问 局域网内的 redis

func InitConnPool(addr, pwd string, db, maxActive, maxidle int) {
	if maxActive <= 0 {
		maxActive = 200
	}

	ConnPool = &redis.Pool{
		MaxActive:   maxActive,
		MaxIdle:     maxidle,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp",
				addr,
				redis.DialPassword(pwd),
				redis.DialDatabase(db))
			if err != nil {
				return nil, err
			}
			return c, err
		},
		TestOnBorrow: PingRedis,
	}
}

func InitConnPoolLocal(addr, pwd string, db, midle int) {
	ConnPoolLocalNet = &redis.Pool{
		MaxIdle:     midle,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp",
				addr,
				redis.DialPassword(pwd),
				redis.DialDatabase(db))
			if err != nil {
				return nil, err
			}
			return c, err
		},
		TestOnBorrow: PingRedis,
	}
}

func PingRedis(c redis.Conn, t time.Time) error {
	_, err := c.Do("ping")
	if err != nil {
		log.Println("[ERROR] ping redis fail", err)
	}
	return err
}
