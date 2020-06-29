package redispool

import (
	"github.com/garyburd/redigo/redis"
	"log"
	"time"
)

var ConnPool *redis.Pool
var ConnPoolLocalNet *redis.Pool   // 访问 局域网内的 redispool

func InitConnPool(addr, pwd string, db, midle int) {

	ConnPool = &redis.Pool{
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
		log.Println("[ERROR] ping redispool fail", err)
	}
	return err
}