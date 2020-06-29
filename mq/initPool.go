
package mq

import (
	"github.com/streadway/amqp"
	//"log"
	"time"
)

var ConnPool *Pool

func InitConnPool(addr, addr1, addr2 string, maxidle int) {

	ConnPool = &Pool{
		MaxIdle:     maxidle ,
		IdleTimeout: 240 * time.Second,
		Dial: func() (*amqp.Connection, error) {
			var c *amqp.Connection
			var err error

			c, err = amqp.Dial(addr)
			if err == nil {
				return c, nil
			}

			if addr1 != "" {
				c, err = amqp.Dial(addr1)
				if err == nil {
					return c, nil
				}
			}

			if addr2 != "" {
				c, err = amqp.Dial(addr2)
				if err == nil {
					return c, nil
				}
			}

			return nil, err
		},
		TestOnBorrow: nil,
	}
}
