BIN  := wanlab-linux

.PHONY: all test vet build deploy smoke

all: test build

test:            ## 纯函数单测(不联网)
	go test -count=1 ./...

vet:
	go vet ./...

build:           ## 编译 linux/amd64 单二进制
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $(BIN) .

deploy: build    ## 本机安装(在部署机上执行): 停服务 -> 换二进制 -> 启服务
	systemctl stop wanlab
	install -m 755 $(BIN) /opt/wanlab/wanlab
	systemctl start wanlab

smoke:           ## 线上冒烟
	@curl -s -m 10 http://127.0.0.1:8688/api/status | head -c 240; echo
	@curl -s -m 10 http://127.0.0.1:8688/api/wanrate | head -c 240; echo
