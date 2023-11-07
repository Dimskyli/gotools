package redispool

import (
	"context"
	"fmt"
	"time"

	"github.com/gomodule/redigo/redis"
)

// listenPubSubChannels listens for messages on Redis pubsub channels. The
// onStart function is called after the channels are subscribed. The onMessage
// function is called for each message.
// 这几种情况会退出 : 连接失败, 订阅失败, ping失败, sub接受消息异常, 收消息后处理返回异常, 上下文cancel取消
func ListenPubSubChannels(ctx context.Context, redisServerAddr string, pass string, db int,
	onStart func() error,
	onMessage func(channel string, data []byte) error,
	channels ...string) error {

	// A ping is set to the server with this period to test for the health of
	// the connection and server.
	const healthCheckPeriod = time.Minute

	c, err := redis.Dial("tcp", redisServerAddr,
		redis.DialPassword(pass), redis.DialDatabase(db),
		// Read timeout on server should be greater than ping period.
		redis.DialReadTimeout(healthCheckPeriod+10*time.Second),
		redis.DialWriteTimeout(10*time.Second))
	if err != nil {
		//fmt.Println(err)
		return err
	}
	defer c.Close()

	psc := redis.PubSubConn{Conn: c}

	if err := psc.Subscribe(redis.Args{}.AddFlat(channels)...); err != nil {
		//fmt.Println(err)
		return err
	}
	//fmt.Println("PubSubConn ok.")

	done := make(chan error, 1)

	// Start a goroutine to receive notifications from the server.
	go func() {
		for {
			switch n := psc.Receive().(type) {
			case error:
				done <- n
				return
			case redis.Message:
				if err := onMessage(n.Channel, n.Data); err != nil {
					done <- err
					return
				}
			case redis.Subscription:
				switch n.Count {
				case len(channels):
					// Notify application when all channels are subscribed.
					if err := onStart(); err != nil {
						done <- err
						return
					}
				case 0:
					// Return from the goroutine when all channels are unsubscribed.
					done <- nil
					return
				}
			}
		}
	}()

	ticker := time.NewTicker(healthCheckPeriod)
	defer ticker.Stop()

loop:
	for err == nil {
		select {
		case <-ticker.C:
			// Send ping to test health of connection and server. If
			// corresponding pong is not received, then receive on the
			// connection will timeout and the receive goroutine will exit.
			if err = psc.Ping(""); err != nil {
				break loop // return err // 是不是更好些 ?
			}
		case <-ctx.Done():
			break loop
		case err := <-done:
			// Return error from the receive goroutine.
			return err
		}
	}

	// Signal the receiving goroutine to exit by unsubscribing from all channels.
	psc.Unsubscribe()

	// Wait for goroutine to complete.
	return <-done
}

//func publish() {
//	c, err := dial()
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	defer c.Close()
//
//	c.Do("PUBLISH", "c1", "hello")
//	c.Do("PUBLISH", "c2", "world")
//	c.Do("PUBLISH", "c1", "goodbye")
//}

// This example shows how receive pubsub notifications with cancelation and
// health checks.
func ExamplePubSubConn() {
	redisServerAddr := "127.0.0.1:6379" // addr := fmt.Sprintf("%v:%d", *serverAddress, *serverBasePort)
	ctx, cancel := context.WithCancel(context.Background())

	err := ListenPubSubChannels(ctx,
		redisServerAddr, "", 0,
		func() error {
			// The start callback is a good place to backfill missed
			// notifications. For the purpose of this example, a goroutine is
			// started to send notifications.
			//go publish()
			return nil
		},
		func(channel string, message []byte) error {
			fmt.Printf("channel: %s, message: %s\n", channel, message)

			// For the purpose of this example, cancel the listener's context
			// after receiving last message sent by publish().
			if string(message) == "goodbye" {
				cancel()
			}
			return nil
		},
		"c1",
		"c2") // 阻塞 不返回

	if err != nil {
		fmt.Println(err)
		return
	}

	// Output:
	// channel: c1, message: hello
	// channel: c2, message: world
	// channel: c1, message: goodbye
}
