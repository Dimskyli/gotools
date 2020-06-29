package mq

import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
	"sync"
	"time"
)

type Consumer struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	exchange string 
	exchangeType string 
	queueName string 
	key 	string 
	tag     string                       // "simple-consumer", "AMQP consumer tag (should not be blank)"
	done    chan error                   // 所有消息处理完后，写入一个标记，然后才能关闭
	mu      sync.Mutex
	stop    bool   						 // 停服的标记位  
	handler func(string) (string, error) // 回调方法
}

func NewConsumer(exchange, exchangeType, queueName, key, ctag string,
	handler func(string) (string, error)) (*Consumer, error) {
	
	c := &Consumer{
		conn:    nil,
		channel: nil,
		exchange: 		exchange, 
		exchangeType: 	exchangeType, 
		queueName: 		queueName,
		key: 	 key, 
		tag:     ctag,
		done:    make(chan error),
		stop:    false, 
		handler: handler,
	}
	return c, nil
}



func (c *Consumer) StartUp() error {
	var err error

	//tryMax := ConnPool.ActiveCount() + 4 //  这样处理 就保证了 把活动的连接全部试一次， 如果连接都失效了， 一定会有一次使用备用地址
	tryN := 0 // 监控 重试次数 

	RETRY:
	tryN += 1 

	log.Println("Consumer Start Up ...", c.tag )
	
	c.conn, err = ConnPool.Get()  // 从池中获取连接 //c.conn, err = amqp.Dial(amqpURI)
	if err != nil {
		log.Println("[ERROR] dial, try again", err, tryN)
		time.Sleep(5 * time.Second)
		goto RETRY 
	}

	// 有关闭行为时， 才执行，然后退出
	go func() {
		log.Printf("closing: %s", <-c.conn.NotifyClose(make(chan *amqp.Error)))
	}()

	log.Printf("got Connection, getting Channel")
	c.channel, err = c.conn.Channel()
	if err != nil {
		log.Println("error channel", err)
		goto RETRY 
	}

	log.Printf("got Channel, declaring Exchange (%q)", c.exchange)
	if err = c.channel.ExchangeDeclare(
		c.exchange,     // name of the exchange
		c.exchangeType, // type
		true,        // durable
		false,        // delete when complete
		false,        // internal
		false,        // noWait
		nil,          // arguments
	); err != nil {
		log.Println("error", err)
		panic(fmt.Sprintf("Exchange Declare: %s", err))
	}

	log.Printf("declared Exchange, declaring Queue %q", c.queueName)
	queue, err := c.channel.QueueDeclare(
		c.queueName, // name of the queue
		true,     // durable
		false,     // delete when usused
		false,     // exclusive
		false,     // noWait
		nil,       // arguments
	)
	if err != nil {
		log.Println("error", err)
		panic(fmt.Sprintf("Queue Declare: %s", err))
	}

	log.Printf("declared Queue (%q %d messages, %d consumers), binding to Exchange (key %q)",
		queue.Name, queue.Messages, queue.Consumers, c.key)

	if err = c.channel.QueueBind(
		queue.Name, // name of the queue
		c.key,        // bindingKey
		c.exchange,   // sourceExchange
		false,      // noWait
		nil,        // arguments
	); err != nil {
		log.Println("error", err)
		panic(fmt.Sprintf("Queue Bind: %s", err))
	}

	err = c.channel.Qos(1, 0, false)
	if err != nil {
		log.Println("error", err)
		panic(fmt.Sprintf("basic.qos: %s", err))
	}
	
	log.Printf("Queue bound to Exchange, starting Consume (consumer tag %q)", c.tag)
	deliveries, err := c.channel.Consume(
		queue.Name, // name
		c.tag,      // consumerTag,
		false,      // noAck
		false,      // exclusive
		false,      // noLocal
		false,      // noWait
		nil,        // arguments
	)
	if err != nil {
		log.Println("error", err)
		panic(fmt.Sprintf("Queue Consume: %s", err))
	}

	handle(deliveries, c.done, c.handler)  // 正常情况下是不退出的 

	// handle 如果退出了， 一定是 关闭了，或是异常了， 如果异常需要重连 

	c.mu.Lock()
	shutdown := c.stop  // 判断是否停服
	c.mu.Unlock()

	if shutdown == true {
		log.Println("Consumer handle stop ")
		c.done <- nil 
	} else {	
		log.Println("Consumer Restart ") 
		goto RETRY
	}

	return err 
}


func (c *Consumer) Shutdown() error {
	c.mu.Lock()
	c.stop = true 
	c.mu.Unlock()

	if c.conn != nil && c.channel != nil {
		// will close() the deliveries channel
		if err := c.channel.Cancel(c.tag, true); err != nil {
			return fmt.Errorf("Consumer cancel failed: %s", err)
		}
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("AMQP connection close error: %s", err)
		}
		defer log.Printf("AMQP shutdown OK")
		// wait for handle() to exit
		return <-c.done
	} else {
		// 在重连的等待中  conn 可能是 nil ，所以直接关闭不用等待 
		return nil 
	}

}

func handle(deliveries <-chan amqp.Delivery, done chan error, handler func(string) (string, error)) {
	for d := range deliveries {

		if handler != nil {
			// 外部的回调方法
			//go func(){
			response, err := handler(string(d.Body))
			if d.CorrelationId != "" {
				log.Printf("response : %s", response)
			}
			if err == nil {  // 正确处理了， 返回 ack ， 否则不处理 
				d.Ack(false) // false 单次 ack确认
			}else {
				log.Printf("mq message Nack")
				// 这要注意了
				// 1 如果不回复 ack ， msg没有超时的情况下，是不会分发给下一个 consumer 的，只有前一个consumber关闭后，才会重新开始分发
				// 2 如果回复 reject(true) 在其他channel重新分发 
				d.Nack(false, true)  // 重新在其他 channle 上投递 , true 不删除 , 多个consumer 如果都不处理，会存在循环投递
			}
			//}()
		} else {
			log.Printf(
				"got %dB delivery, ignore: [%v] %q",
				len(d.Body),
				d.DeliveryTag,
				d.Body,
			)
		}
	}
	log.Printf("handle: deliveries channel closed")
}
