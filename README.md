# BPF-XDP 

eBPF (extended Berkeley Packet Filter) XDP (Express Data Path) programs are a type of eBPF program that are attached to a network interface using the XDP hook. The XDP hook is a low-level hook that allows eBPF programs to be executed early in the packet receive path, before the packet is passed up the network stack.

XDP programs can be used to perform various packet processing tasks, such as filtering, forwarding, modifying, or collecting statistics on network traffic. Because they execute in the kernel, they have access to low-level network metadata and can be used to implement advanced networking features that would otherwise require kernel modifications.

The XDP hook (eXpress Data Path) is a hook in the Linux kernel that allows for packet processing at the earliest possible stage in the networking stack. It provides a low-level interface to packet filtering and manipulation, and is often used for high-performance network processing.

XDP programs are written in C and compiled into eBPF bytecode using the LLVM compiler. The eBPF bytecode is then loaded into the kernel using the bpf system call. Once loaded, the XDP program can be attached to a network interface.

## Cilium ebpf

Cilium is an open-source project that provides a networking and security solution for containerized applications that leverages eBPF technology. The __Cilium eBPF library__ provides a Go interface to the eBPF subsystem, making it easier to write eBPF programs in Go.

The Cilium eBPF library is a Go library that provides abstractions over eBPF programs and maps, as well as helpers for loading and attaching eBPF programs to various hooks in the Linux kernel.

[Cilium ebpf](https://github.com/cilium/ebpf)

[Documentation](https://pkg.go.dev/github.com/cilium/ebpf)

### Architecture of library

[Refer for architecture](https://github.com/cilium/ebpf/blob/master/ARCHITECTURE.md)

```mermaid
graph RL
    Program --> ProgramSpec --> ELF
    btf.Spec --> ELF
    Map --> MapSpec --> ELF
    Links --> Map & Program
    ProgramSpec -.-> btf.Spec
    MapSpec -.-> btf.Spec
    subgraph Collection
        Program & Map
    end
    subgraph CollectionSpec
        ProgramSpec & MapSpec & btf.Spec
    end
```

## XDP hook

 The __XDP hook (eXpress Data Path)__ is a hook in the Linux kernel that allows for packet processing at the earliest possible stage in the networking stack. It provides a low-level interface to packet filtering and manipulation, and is often used for high-performance network processing.
 The XDP hook is one of the hooks that Cilium provides an abstraction for.

## Cilium ebpf project structure

<!-- Code Blocks -->
```
$tree xdp
xdp
|----bpf_bpfeb.go
|----bpf_bpfeb.o
|----bpf_bpfel.go
|----bpf_bpfel.o
|----main.go
|____xdp.c    

0 directories,6 files
```
The ebpf program's source code file,__xdp.c__ in the diagram, is compiled using __bpf2go__, a code generation tool provided by cilium/ebpf. 
bpf2go uses the clang compiler to generate two ebpf bytecode files: "bpf_bpfeb.o" for big-endian and "bpf_bpfel.o" for little-endian systems. Additionally, bpf2go generates "bpf_bpfeb.go" or "bpf_bpfel.go" files based on the corresponding bytecode file. 
These go source files contain the ebpf program's bytecode as binary data.

The "main.go" file is responsible for the user state of the ebpf program. Compiling "main.go" with either "bpf_bpfeb.go" or "bpf_bpfel.go" creates the final ebpf program.



![Untitled-2023-03-22-2025](https://user-images.githubusercontent.com/128127818/227079552-b03c3d31-d7af-48a7-b49f-c52f91744297.png)



[Read more about bpf2go](https://github.com/cilium/ebpf/tree/master/cmd/bpf2go)

## Userspace program written in __Go__ using Cilium ebpf library 

Major components you might find in this userspace eBPF program written using the Cilium eBPF library in Go are as follows:

1. **Loading** pre-compiled eBPF programs into the kernel
1. **Attaching** the eBPF program to a network interface using XDP (eXpress Data Path)
1. **Printing** the contents of the BPF hash map (source IP address -> packet count) to stdout every second using a ticker.
1. A helper function formatMapContents() to **format the contents** of the BPF hash map as a string.
1. **Error handling** for all potential errors, such as failing to load the eBPF program or failing to attach it to the network interface.

```Go

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

```
Import statements for required Go packages and the Cilium eBPF library and link package.


```Go

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I../headers

```
This part of the code generates Go code that includes the compiled eBPF program as an embedded byte array, which is then used in the main Go program without relying on external files.
The comment indicates following line is a __Go generate directive__, genertaes Go code that includes the compiled eBPF program, defined in the C source file xdp.c, as an embedded byte array.
The __$BPF_CLANG__ and __$BPF_CFLAGS__ environment variables are used as parameters for the command, and they are expected to be set by the Makefile. These environment variables specify the C compiler and its flags to use when compiling the eBPF program.

```Go
func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}
```
We check that the user has provided a command-line argument specifying the network interface to attach the XDP program to. If not, the program exits with a fatal error message.
We use the network interface name specified by the user to look up the corresponding interface object using the `net.InterfaceByName()` function. If the lookup fails, the program exits with a fatal error message.

```Go
	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()
```
This creates an empty `bpfObjects` struct and then loads pre-compiled eBPF programs into the kernel using the `loadBpfObjects()` function. If the load fails, the program exits with a fatal error message. If the load succeeds, a `defer` statement is used to ensure that the `Close()` method of the `bpfObjects` struct is called at the end of the function, regardless of whether it returns normally or with an error.

```Go
	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()
	
	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
```

`link.AttachXDP()` attaches the XDP program to the specified network interface. It returns a handle to the XDP program that can be used to detach it later. The function takes an `XDPOptions` struct that specifies the program and the network interface. `objs.XdpProgFunc` is the eBPF program's entry point function.
<p> If an error occurs while attaching the XDP program, the program exits with a fatal error message.defer l.Close() defers the closing of the XDP program handle until the end of the function.</p>

```Go
	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.XdpStatsMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}
```
This code prints the contents of the __BPF hash map__ to the console every second using a ticker.`time.NewTicker(1 * time.Second)` creates a ticker that will send a message every second.`defer ticker.Stop()` defers the stopping of the ticker until the end of the function.
The `for range ticker.C` loop receives messages from the ticker channel.
`formatMapContents()` takes the eBPF map and returns a formatted string of the map's contents.
If there is an error reading the map, the error message is printed to the console, and the loop continues.

```Go
func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key []byte
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := net.IP(key) // IPv4 source address in network byte order.
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))
	}
	return sb.String(), iter.Err()

```

This takes an eBPF map as input, iterates over the key-value pairs in the map, and returns a string representation of the map's contents. Here's what each line of the function does:

`func formatMapContents(m *ebpf.Map) (string, error) {` defines the function with a parameter `m` representing the eBPF map to be formatted and a return type of a string and an error.`var (` defines multiple variables in a single line.
`sb strings.Builder` declares a `strings.Builder` variable named `sb`. This variable is used to build up the formatted string.
`key []byte` declares a `[]byte` variable named `key`. This variable is used to store the key of the current key-value pair during iteration.
`val uint32` declares a `uint32` variable named `val`. This variable is used to store the value of the current key-value pair during iteration.
`iter := m.Iterate()` creates a new iterator for the given eBPF map `m`. The `Iterate` method returns an iterator object which is used to iterate over the map's key-value pairs.
`for iter.Next(&key, &val) {` starts a loop that iterates over the map's key-value pairs. The `Next` method of the iterator object returns `true` if there are more key-value pairs to be iterated over, and assigns the current key and value to the variables passed as pointers to it.
`sourceIP := net.IP(key)` converts the `[]byte` key into an `net.IP` object representing the IPv4 source address in network byte order. This is necessary because the eBPF map stores IP addresses as byte arrays.
`packetCount := val` stores the value of the current key-value pair in the `packetCount` variable.
`sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))` formats the current key-value pair as a string and writes it to the `sb` string builder.`return sb.String(), iter.Err()` returns the final string representation of the eBPF map's contents as well as any error that occurred during iteration. The `String` method of the `strings.Builder` object returns the built string, and the `Err` method of the iterator object returns any error that occurred during iteration.
