package mq

import (
	//"bytes"
	"container/list"
	//"crypto/rand"
	//"crypto/sha1"
	"errors"
	//"io"
	//"strconv"
	"sync"
	"time"
	"log"

	"github.com/streadway/amqp"
)


var nowFunc = time.Now // for testing
var ErrPoolExhausted = errors.New(": connection pool exhausted")  // 资源用完了


type Pool struct {

	Dial func() (*amqp.Connection, error)

	TestOnBorrow func(c *amqp.Connection, t time.Time) error

	// Maximum number of idle connections in the pool.
	MaxIdle int

	// Maximum number of connections allocated by the pool at a given time.
	// When zero, there is no limit on the number of connections in the pool.
	MaxActive int

	// Close connections after remaining idle for this duration. If the value
	// is zero, then idle connections are not closed. Applications should set
	// the timeout to a value less than the server's timeout.
	IdleTimeout time.Duration

	// If Wait is true and the pool is at the MaxActive limit, then Get() waits
	// for a connection to be returned to the pool before returning.
	Wait bool

	// mu protects fields defined below.
	mu     sync.Mutex
	cond   *sync.Cond
	closed bool
	active int

	// Stack of idleConn with most recently used at the front.
	idle list.List
}

type idleConn struct {
	c *amqp.Connection
	t time.Time
}


func NewPool(newFn func() (*amqp.Connection, error), maxIdle int) *Pool {
	log.Println("init mq conn pool ...")
	return &Pool{Dial: newFn, MaxIdle: maxIdle}
}

// 获取连接
func (p *Pool) Get() (*amqp.Connection, error) {
	c, err := p.get()
	return c, err
}

// 归还连接
func (p *Pool) Put(c *amqp.Connection) (error) {
	err := p.put(c, false)
	return err
}


func (p *Pool) ActiveCount() int {
	p.mu.Lock()
	active := p.active
	p.mu.Unlock()
	return active
}


func (p *Pool) Close() error {
	p.mu.Lock()
	idle := p.idle
	p.idle.Init()
	p.closed = true
	p.active -= idle.Len()
	if p.cond != nil {
		p.cond.Broadcast()
	}
	p.mu.Unlock()
	for e := idle.Front(); e != nil; e = e.Next() {
		e.Value.(idleConn).c.Close()
	}
	log.Println("Closed mq conn pool")
	return nil
}

// release decrements the active count and signals waiters. The caller must
// hold p.mu during the call.
func (p *Pool) release() {
	p.active -= 1
	if p.cond != nil {
		p.cond.Signal()
	}
}

// get prunes stale connections and returns a connection from the idle list or
// creates a new connection.
func (p *Pool) get() (*amqp.Connection, error) {
	p.mu.Lock()

	// Prune stale connections.
	if timeout := p.IdleTimeout; timeout > 0 {
		// 检查所有 空闲的连接 是否需要回收
		for i, n := 0, p.idle.Len(); i < n; i++ {
			e := p.idle.Back()
			if e == nil {
				break
			}
			ic := e.Value.(idleConn)
			if ic.t.Add(timeout).After(nowFunc()) { // 还没有超时
				break
			}

			// 超时 开始回收
			p.idle.Remove(e)
			p.release()
			p.mu.Unlock()

			ic.c.Close() // 关闭连接

			p.mu.Lock()
		}
	}

	for {

		// Get idle connection.

		for i, n := 0, p.idle.Len(); i < n; i++ {
			e := p.idle.Front()
			if e == nil {
				break // 没有空闲的， 需要新打开
			}

			ic := e.Value.(idleConn) // 取到一个连接
			p.idle.Remove(e)

			test := p.TestOnBorrow
			p.mu.Unlock()

			// 开始测试 连接是否可用
			if test == nil || test(ic.c, ic.t) == nil {
				return ic.c, nil
			}

			// 连接 异常，不可用 ，关闭掉
			ic.c.Close()

			p.mu.Lock()
			p.release()
		}

		// Check for pool closed before dialing a new connection.

		if p.closed {
			p.mu.Unlock()
			return nil, errors.New(": get on closed pool")
		}

		// Dial new connection if under limit.

		if p.MaxActive == 0 || p.active < p.MaxActive {
			dial := p.Dial
			log.Println("dial new amqp ...")
			p.active += 1
			p.mu.Unlock()

			c, err := dial()
			if err != nil {
				p.mu.Lock()
				p.release()
				p.mu.Unlock()
				c = nil
			}
			return c, err
		}

		if !p.Wait {
			p.mu.Unlock()
			return nil, ErrPoolExhausted
		}

		if p.cond == nil {
			p.cond = sync.NewCond(&p.mu)
		}
		p.cond.Wait() // get 不到连接，只有等待
	}
}


//归还到池中
func (p *Pool) put(c *amqp.Connection, forceClose bool) error {

	p.mu.Lock()
	if !p.closed  && !forceClose {
		p.idle.PushFront(idleConn{t: nowFunc(), c: c})
		if p.idle.Len() > p.MaxIdle {
			c = p.idle.Remove(p.idle.Back()).(idleConn).c
		} else {
			c = nil
		}
	}

	if c == nil {
		if p.cond != nil {
			p.cond.Signal()
		}
		p.mu.Unlock()
		return nil
	}

	p.release()
	p.mu.Unlock()
	return c.Close()
}



