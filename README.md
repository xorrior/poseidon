# Poseidon
Golang Apfell Agent

## Build Instructions

Fill out the `profile.go` file with your C2 Listener information.

Then navigate to `Manage Operations > Payload Management` on the Apfell server, and import the `poseidon.json` file. This registers the payload with the Apfell server as an externally hosted payload.

You can then register the payload with the C2 server via `Create Components > Create Payload` on the Apfell server, and stuff the GUID and other relevant information into `profile.go`

Then build the agent _either_ on the target operating system you wish to run the agent against or compile using xgo (https://hub.docker.com/r/karalabe/xgo-latest/builds)

`go build -tags=default cmd/agent/main.go`
or
`go build -tags=restfulpatchthrough cmd/agent/main.go`

Once the agent is built, all that's left is to execute.

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
jobs                List currently running and stoppable jobs.
jobkill             Kill a job by the specified GUID.
kill                Kill a process designated by PID.
cp                  Copy a file.
mv                  Move a file.
rm                  Delete a file.
mkdir               Create a directory.
pwd                 Print working directory.
drives              List currently mounted drives, their description, and current hard-disk usage.
getuser             List information about the current user.
getenv              Retrieve current environment variables.
setenv              Set an environment variable.
unsetenv            Delete an environment variable.
```

## Commands per OS

| Command | Windows | MacOS | Linux |
| ------- | ------- | ----- | ----- |
| exit | &#9745; | &#9745; | &#9745; |
| shell | &#9745; | &#9745; | &#9745; |
| screencapture | &#9745; | &#9745; | &#9745; |
| download | &#9745; | &#9745; | &#9745; |
| upload | &#9745; | &#9745; | &#9745; |
| inject |  | &#9745; |  |
| shinject | &#9745; |  |  |
| ps | &#9745; | &#9745; | &#9745; |
| sleep | &#9745; | &#9745; | &#9745; |
| cat | &#9745; | &#9745; | &#9745; |
| cd | &#9745; | &#9745; | &#9745; |
| ls | &#9745; | &#9745; | &#9745; |
| keys |  | &#9745; | &#9745; |
| triagedirectory | &#9745; | &#9745; | &#9745; |
| sshauth | &#9745; | &#9745; | &#9745; |
| portscan | &#9745; | &#9745; | &#9745; |
| getprivs | &#9745; |  |  |
| execute-assembly | &#9745; |  |  |
| jobs | &#9745; | &#9745; | &#9745; |
| jobkill | &#9745; | &#9745; | &#9745; |
| kill |  &#9745; | &#9745; | &#9745; |
| cp | &#9745; | &#9745; | &#9745; |
| mv | &#9745; | &#9745; | &#9745; |
| rm | &#9745; | &#9745; | &#9745; |
| mkdir | &#9745; | &#9745; | &#9745; |
| pwd | &#9745; | &#9745; | &#9745; |
| drives | &#9745; | &#9745; | &#9745; |
| getuser | &#9745; | &#9745; | &#9745; |
| getenv | &#9745; | &#9745; | &#9745; |
| setenv | &#9745; | &#9745; | &#9745; |
| unsetenv | &#9745; | &#9745; | &#9745; |

## Killable Jobs

Due to the way Go-routines function, it's difficult if not impossible to kill them. As a result, only certain long-running tasks are able to receive a "kill" signal. The current list of killable jobs are:
- `executeassembly`
- `triagedirectory`
- `portscan`
