# ROCO (Route Coordinator)

Roco is a network proxy agent that can proxy all packets bound to unreachable endpoint via a reachable relay. ROCO is short for route coordinator.

Its inspired by sshuttle but does not rely on SSH transport or SSH encryption.

Roco is designed for simplicity and sole task of proxying TCP and UDP packets to an unreachable target. Its essentially a lightweight router that can proxy an entire network over a hop.

## Quickstart


## Building

single binary for all linux versions (musl-linked binary)


    docker run --rm -v $PWD:/w -w /w crystallang/crystal:1.18.0-alpine \
    crystal build src/roco.cr -o bin/roco --release --static
