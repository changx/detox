package main

import (
	"github.com/changx/detox/dnsserver"
	"github.com/labstack/echo"
	"net/http"
)

func main() {

	go dnsserver.StartDNSServer()

	engine := echo.New()

	engine.GET("/", func(context echo.Context) error {
		context.String(http.StatusOK, "hi")
		return nil
	})

	engine.Start(":80")


}
