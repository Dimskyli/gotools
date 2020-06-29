package mq

import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
)

func Publish(exchange, exchangeType, routingKey, body string, reliable bool) error {

	tryMax := ConnPool.ActiveCount() + 1 //  这样处理 就保证了 把活动的连接全部试一次， 如果连接都失效了， 一定会有一次使用备用地址
	tryN := 0                            // 监控 重试次数

RETRY:
	tryN += 1

	//log.Printf("dialing %q", amqpURI)
	connection, err := ConnPool.Get() // amqp.Dial(amqpURI)
	if err != nil {
		if tryN < tryMax {
			log.Println("get conn from mq connpool err, try again", tryN)
			goto RETRY
		}
		return fmt.Errorf("Dial: %s", err)
	}

	//log.Printf("got Connection, getting Channel")
	channel, err := connection.Channel()
	if err != nil {
		if tryN < tryMax {
			goto RETRY
		}
		return fmt.Errorf("Channel: %s", err)
	}

	//log.Printf("got Channel, declaring %q Exchange (%q)", exchangeType, exchange)
	if err := channel.ExchangeDeclare(
		exchange,     // name
		exchangeType, // type
		true,         // durable
		false,        // auto-deleted
		false,        // internal
		false,        // noWait
		nil,          // arguments
	); err != nil {
		if tryN < tryMax {
			goto RETRY
		}
		return fmt.Errorf("Exchange Declare: %s", err)
	}

	// Reliable publisher confirms require confirm.select support from the
	// connection.
	var ack, nack chan uint64
	if reliable {
		//log.Printf("enabling publishing confirms.")
		if err := channel.Confirm(false); err != nil {
			return fmt.Errorf("Channel could not be put into confirm mode: %s", err)
		}

		ack, nack = channel.NotifyConfirm(make(chan uint64, 1), make(chan uint64, 1))

		// defer confirmOne(ack, nack)
	}

	//log.Printf("MQ, publishing %dB body (%q)", len(body), body)
	if err = channel.Publish(
		exchange,   // publish to an exchange
		routingKey, // routing to 0 or more queues
		false,      // mandatory
		false,      // immediate
		amqp.Publishing{
			Headers:         amqp.Table{},
			ContentType:     "text/plain",
			ContentEncoding: "",
			Body:            []byte(body),
			DeliveryMode:    amqp.Transient, // 1=non-persistent, 2=persistent
			Priority:        0,              // 0-9
			// a bunch of application/implementation-specific fields
		},
	); err != nil {
		if tryN < tryMax {
			goto RETRY
		}
		return fmt.Errorf("Exchange Publish: %s", err)
	}

	if reliable {
		// 失败后重试 待添加
		select {
		case tag := <-ack:
			log.Printf("confirmed delivery with delivery tag: %d", tag)
		case tag := <-nack:
			log.Printf("failed delivery of delivery tag: %d", tag)
		}
	}

	channel.Close()          // 归还前先把channel关闭了
	ConnPool.Put(connection) // 归还连接 

	return nil
}

func confirmOne(ack, nack chan uint64) {
	//log.Printf("waiting for confirmation of one publishing")

	select {
	case tag := <-ack:
		log.Printf("confirmed delivery with delivery tag: %d", tag)
	case tag := <-nack:
		log.Printf("failed delivery of delivery tag: %d", tag)
	}
}
