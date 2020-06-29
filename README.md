# gotools

## mq连接池

1、导入package： 
```$xslt
go get github.com/dimskyli/gotools/mq
``` 

2、使用连接池：

>在mq中声明了一个全局的mq连接池，[var ConnPool *Pool], 因此在使用mq包时不需要调用者自己声明，mq包内部会自动从mq池中取空闲的连接

```go
package main

import (
 "github.com/dimskyli/gotools/mq"
 "log"
)

//InitConnPool() 可以传入三个mq连接地址，默认第一个连接失败会切换到其他地址
func Init(){
    mq.InitConnPool(Addr,Addr1, Addr2, MaxIdle)
}

func main()  {
	Init() //初始化
	
	//mq 推送消息为json字符串
	strtmp := `{name:"test"}`
	
    mq.Publish("3rd.in.exchange", "direct", "sms.key", strtmp, true) //publish
    
    worker := CommonConsumer(RouterMqExchange, RouterMqQueue, RouterMqKey, RouterMqTag)
    
    //启动消费者
    go worker.StartUp()
    
    select{}
}

//创建消费者
func CommonConsumer(exchange, queue, key, ctag string) *mq.Consumer {
	consumer, err := mq.NewConsumer(
		exchange,
		"direct",
		queue,
		key,
		ctag,    //simple-consumer
		handler) // call back Fun
	log.Fatal(err, "[ERROR] Consumer 启动失败")
	return consumer
}

//消费者业务逻辑
func handler(in string) (out string, err error) {

	log.Println("[mq json] json:", in)
	
	//TODO...
	return "", nil
}
```


