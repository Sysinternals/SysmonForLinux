# Networking

## Introduction

As mentioned in a previous chapter, tracking network events is difficult from a 
syscall-monitoring perspective. This chapter explains how other tracepoints can 
help. Only TCP and UDP are covered.

## The problem with syscalls

Network connections can be established using the following syscalls:

* Outbound TCP - socket(), optionally bind(), connect().
* Inbound TCP - socket(), bind(), accept().
* Outbound UDP - socket(), optionally bind(), sendto().
* Inbound UDP - socket(), bind(), recvfrom().

If an outbound TCP connection fails to bind() to a local port/address, then a 
syscall-monitor would not be able to easily work out the local port/address 
from the kernel information alone. It could obtain the remote port/address from 
the connect() sockaddr (with a TOCTOU race condition), or could look up the 
file descriptor in /proc to obtain local and remote ports/addresses, with a 
potential race condition and performance hit.

If an inbound TCP connection fails to bind() to a specific address, then a 
syscall-monitor would not easily be able to work out the local address. If the 
accept() call had a NULL sockaddr pointer, then the remote port/address would 
be unknown. Again, lookup in /proc is possible from the file descriptor.

Similar scenarios exist for UDP, with the added problem that UDP is 
connectionless, so reporting 'UDP connections' doesn't really make sense. 
Sysmon reports each 'new' UDP transmission, where 'new' means it hasn't seen 
the same source/remote/address/port combination for a defined period (half an 
hour).

## TCP Outbound

Sysmon uses the sock/inet\_sock\_set\_state tracepoint for monitoring new TCP 
connections (tcp/tcp\_set\_state for kernel v4.15). This tracepoint gets hit 
every time a TCP connection changes state, and includes all the address/port 
parameters that should be reported. The problem with it, however, is down to 
the asynchronous nature of TCP connection establishment.

Outbound TCP connections are initiated by an application, and a SYN packet is 
sent to the destination. The tracepoint is hit with the CLOSED to SYN\_SENT 
transition; the task struct available to the tracepoint program is the task 
struct for the application that initiated the connection. All good, except the 
connection isn't technically established at this point - the destination could 
ignore or reject it, for example.

The rest of the handshake is then handled by the kernel, a driver or a daemon, 
outside the context of the application. When the SYN/ACK packet is received, an 
ACK is automatically sent and the connection state changed to ESTABLISHED. This 
time, the tracepoint program gets the task struct of the driver or daemon that 
handled the state change, instead of the application that initiated the 
connection.

The easy solution is to track the two state changes, in eBPF or in userland, 
storing the details against the task PID on the SYN\_SENT transition, and then 
matching them up on the ESTABLISHED transition. This particular tracking is 
suited to userland where hashes can grow arbitrarily (to accommodate numerous 
half-open connections). An ageing-off data structure is recommended, to delete 
old half-open states when stale. If the tracking is done in eBPF, then it will 
need to be actively managed from userland to implement the ageing-off (as eBPF 
can't do this itself).

## TCP Inbound

Inbound connection reporting is similar, except both the CLOSED to SYN\_RECV and 
SYN\_RECV to ESTABLISHED transitions occur in the driver or daemon context, 
meaning the task struct and PID is of no use for either state change. In this 
situation, it is possible to track the ESTABLISHED transitions and the 
successful completion of accept() syscalls. Due to the 3-way handshake in TCP, 
if the accept() call has a non-NULL addr parameter, then the contents of this 
will represent the address and port of the remote, initiating system, and only 
one ESTABLISHED connection can exist for each remote address and port 
combination at any one time. These can therefore be matched up and the PID 
(from accept()) matched to the details (from state tracking).

There is a problem if the accept() call has addr set to NULL. In this 
situation, one option is to also track bind() calls, so the file descriptor 
used in the accept() can be matched to the cached one from the bind(), 
revealing at least the local port, which can then be matched against the cached 
connection details. This approach can still fail if the bind() event is missed 
due to system load (perf ring buffer saturated).

Another option would be to look up the file descriptor returned by accept() in 
/proc (falling back to looking up the listening file descriptor given in the 
accept() parameters) and obtaining connection details from there. This approach 
obviously suffers from a TOCTOU race condition.

## UDP Outbound

There is no equivalent in UDP to sock/inet\_sock\_set\_state, so the only 
options are to monitor packets sent and inspect the UDP ones, or to monitor 
sendto()-alike syscalls and to monitor those sent to UDP sockets.

The problem with monitoring the syscalls is that an eBPF hash of all file 
descriptors being sent to, would need to be maintained, indicating whether they 
are UDP file descriptors or not. Each would also need to be resolved in /proc 
in userland resulting in TOCTOU race conditions, which are obviously more 
significant in UDP than TCP.

Fast packet monitoring appears to be the favourable approach. Unfortunately, 
most tracepoints that see packets don't see them in the context of the 
application, so the task struct and PID don't mean anything. Most of the ones 
that do, don't have access to the packet contents. There is one exception: if 
an eBPF program is attached to a raw socket (even if it does nothing), then the 
skb/consume\_skb tracepoint gets hit on outbound packets, when it normally 
wouldn't. A program attached to this tracepoint sees packet contents for 
outbound packets, in the context of the application (so gets task struct and 
PID).

In order to only report 'new' 'connections', an eBPF hash should be maintained 
to log 'connections' that have recently been reported. This hash should be 
managed from userland to age-off stale entries, and to handle saturation. It is 
important that the eBPF program can tell when it has reported the same 
'connection' recently in order to prevent saturating the perf ring buffer with 
events for 'connections' that are not 'new', especially as this program is run 
on every UDP packet.

## UDP Inbound

Unfortunately, there is no equivalent packet monitoring option for inbound, as 
tracepoints either have no access to packet internals (memory is paged out) or 
aren't in the application context (task struct and PID are meaningless).

The best option appears to be to monitor the recvfrom() (and related) syscalls, 
resolve the network parameters from /proc, and maintain an eBPF hash (with 
ageing-off) of known file descriptors and protocols to avoid sending events for 
every related syscall.

An alternative (unexplored) option would be to monitor packets using one of the 
packet options (raw socket, xdp, etc) and maintain an eBPF hash to prevent 
resends; then match up the packet parameters in /proc and reverse that to a 
matching file descriptor inside a /proc/PID directory. This approach would 
require a process cache, and therefore the tracking of fork() and execve(), 
plus rescanning for cache misses.



