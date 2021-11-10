package main

import (
	"fmt"
	"os/exec"

	"github.com/kata-containers/runtime/virtcontainers/pkg/nsenter"
)

func main() {
	ns := nsenter.Namespace{Path: "/var/run/docker/netns/fe346fe75c3e", Type: nsenter.NSTypeNet}
	err := nsenter.NsEnter([]nsenter.Namespace{ns}, run)
	if err != nil {
		fmt.Println("nsenter failed, err:", err)
	} else {
		fmt.Println("nsenter success")
	}
}

func run() error {
	out, err := exec.Command("ip", "link").Output()
	if err == nil {
		fmt.Println("inner namespace:\n", string(out))
	}
	return err
}
