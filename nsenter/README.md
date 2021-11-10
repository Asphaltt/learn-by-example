# An example of nsenter in Go

When I search "golang nsenter", "github.com/kata-containers/runtime/virtcontainers/pkg/nsenter" catches my eyes.

I wanna to use it to `nsenter` a Docker's network namespace, or any other network namespace. The following code makes it.

```go
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
```

What exactly I do is providing the path of namespace. Another way is to provide a PID in the namespace. As the code in `kata-containers/.../nsenter` shows:

```go
		targetNSPath := ns.Path
		if targetNSPath == "" {
			targetNSPath = getNSPathFromPID(ns.PID, ns.Type)
		}
```