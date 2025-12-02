# Protocols (Documentation)

Protocols implemented by nanonext.

For an authoritative guide please refer to the online documentation for
the NNG library at <https://nng.nanomsg.org/man/>.

## Bus (mesh networks)

**\[protocol, bus\]** The bus protocol is useful for routing
applications or for building mesh networks where every peer is connected
to every other peer.

In this protocol, each message sent by a node is sent to every one of
its directly-connected peers. This protocol may be used to send and
receive messages. Sending messages will attempt to deliver to each
directly connected peer. Indirectly-connected peers will not receive
messages. When using this protocol to build mesh networks, it is
therefore important that a fully-connected mesh network be constructed.

All message delivery in this pattern is best-effort, which means that
peers may not receive messages. Furthermore, delivery may occur to some,
all, or none of the directly connected peers (messages are not delivered
when peer nodes are unable to receive). Hence, send operations will
never block; instead if the message cannot be delivered for any reason
it is discarded.

## Pair (two-way radio)

**\[protocol, pair\]** This is NNG's pair v0. The pair protocol
implements a peer-to-peer pattern, where relationships between peers are
one-to-one. Only one peer may be connected to another peer at a time,
but both may send and receive messages freely.

Normally, this pattern will block when attempting to send a message if
no peer is able to receive the message.

## Poly (one-to-one of many)

**\[protocol, poly\]** This is NNG's pair v1 polyamorous mode. It allows
a socket to communicate with multiple directly-connected peers.

If no remote peer is specified by the sender, then the protocol
willselect any available connected peer.

If the peer on the given pipe is not able to receive (or the pipe is no
longer available, such as if the peer has disconnected), then the
message will be discarded with no notification to the sender.

## Push/Pull (one-way pipeline)

In the pipeline pattern, pushers distribute messages to pullers, hence
useful for solving producer/consumer problems.

If multiple peers are connected, the pattern attempts to distribute
fairly. Each message sent by a pusher will be sent to one of its peer
pullers, chosen in a round-robin fashion. This property makes this
pattern useful in load-balancing scenarios.

**\[protocol, push\]** The push protocol is one half of a pipeline
pattern. The other side is the pull protocol.

**\[protocol, pull\]** The pull protocol is one half of a pipeline
pattern. The other half is the push protocol.

## Publisher/Subscriber (topics & broadcast)

In a publisher/subscriber pattern, a publisher sends data, which is
broadcast to all subscribers. The subscriber only see the data to which
they have subscribed.

**\[protocol, pub\]** The pub protocol is one half of a
publisher/subscriber pattern. This protocol may be used to send
messages, but is unable to receive them.

**\[protocol, sub\]** The sub protocol is one half of a
publisher/subscriber pattern. This protocol may be used to receive
messages, but is unable to send them.

## Request/Reply (RPC)

In a request/reply pattern, a requester sends a message to one replier,
who is expected to reply with a single answer. This is used for
synchronous communications, for example remote procedure calls (RPCs).

The request is resent automatically if no reply arrives, until a reply
is received or the request times out.

**\[protocol, req\]** The req protocol is one half of a request/reply
pattern. This socket may be used to send messages (requests), and then
to receive replies. Generally a reply can only be received after sending
a request.

**\[protocol, rep\]** The rep protocol is one half of a request/reply
pattern. This socket may be used to receive messages (requests), and
then to send replies. Generally a reply can only be sent after receiving
a request.

## Surveyor/Respondent (voting & service discovery)

In a survey pattern, a surveyor sends a survey, which is broadcast to
all peer respondents. The respondents then have a chance to reply (but
are not obliged). The survey itself is a timed event, so that responses
received after the survey has finished are discarded.

**\[protocol, surveyor\]** The surveyor protocol is one half of a survey
pattern. This protocol may be used to send messages (surveys), and then
to receive replies. A reply can only be received after sending a survey.
A surveyor can normally expect to receive at most one reply from each
responder (messages may be duplicated in some topologies, so there is no
guarantee of this).

**\[protocol, respondent\]** The respondent protocol is one half of a
survey pattern. This protocol may be used to receive messages, and then
to send replies. A reply can only be sent after receiving a survey, and
generally the reply will be sent to the surveyor from which the last
survey was received.
