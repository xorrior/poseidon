# Poseidon
Golang Apfell Agent

## Build Instructions

Build the agent _either_ on the target operating system you wish to run the agent against or compile using xgo (https://hub.docker.com/r/karalabe/xgo-latest/builds)

`go build -tags=default cmd/agent/main.go`
or
`go build -tags=patchthrough cmd/agent/main.go`

## Supported Commands
```
exit                Stop execution of the agent.
shell               Execute a shell command.
screencapture       Screenshot target desktop.
download            Download a file from the remote system.
upload              Upload a file to the remote system.
inject              Inject a library into a remote process.
shinject            Inject shellcode into a remote process.
ps                  List running processes.
sleep               Set time between checkins.
cat                 Read contents of file.
cd                  Change directory.
ls                  List directory contents.
keys                Retrieve keys from kerberos keychain.
triagedirectory     Search target directory for interesting files.
sshauth             Authenticate to a host or a list of hosts using a username+password/key pair.
portscan            Scan a target for open ports.
getprivs            Enable as many privileges as possible for your current access token.
execute-assembly    Execute a .NET assembly.
```

## Commands per OS

| Command | Windows | MacOS | Linux |
| ------- | ------- | ----- | ----- |
| exit | &#9745; | &#9745; | &#9745; |
| shell | &#9745; | &#9745; | &#9745; |
| screencapture | &#9745; | &#9745; | &#9745; |
| download | &#9745; | &#9745; | &#9745; |
| upload | &#9745; | &#9745; | &#9745; |
| inject | &#9744; | &#9745; | &#9745; |
| shinject | &#9745; | &#9744; | &#9744; |
| ps | &#9745; | &#9745; | &#9745; |
| sleep | &#9745; | &#9745; | &#9745; |
| cat | &#9745; | &#9745; | &#9745; |
| cd | &#9745; | &#9745; | &#9745; |
| ls | &#9745; | &#9745; | &#9745; |
| keys | &#9744; | &#9745; | &#9745; |
| triagedirectory | &#9745; | &#9745; | &#9745; |
| sshauth | &#9745; | &#9745; | &#9745; |
| portscan | &#9745; | &#9745; | &#9745; |
| getprivs | &#9745; | &#9744; | &#9744; |
| execute-assembly | &#9745; | &#9744; | &#9744; |
