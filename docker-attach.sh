#!/usr/bin/env bash
set -euo pipefail

SOCK="${DOCKER_SOCK:-/var/run/docker.sock}"
API="http://localhost/v1.48"
IMAGE="${IMAGE:-node:18-bullseye}"
NAME="runner-api-test-$$"

api() {
  curl --silent --show-error --fail-with-body \
    --unix-socket "$SOCK" "$@"
}

json_field() {
  node -e '
    let s="";
    process.stdin.on("data", d => s+=d);
    process.stdin.on("end", () => {
      const j=JSON.parse(s);
      console.log(j[process.argv[1]] ?? "");
    });
  ' "$1"
}

echo "[*] Checking Docker daemon"
api "$API/_ping"
echo

echo "[*] Existing containers"
api "$API/containers/json?all=true" | node -e '
  let s="";
  process.stdin.on("data",d=>s+=d);
  process.stdin.on("end",()=>{
    for(const c of JSON.parse(s)){
      console.log(`${c.Id.slice(0,12)} ${c.State} ${c.Image}`);
    }
  });
'

echo "[*] Creating isolated container"

BODY=$(cat <<EOF
{
  "Image": "$IMAGE",
  "Cmd": ["/bin/sh", "-c", "sleep 300"],
  "HostConfig": {
    "Privileged": false,
    "ReadonlyRootfs": true,
    "CapDrop": ["ALL"],
    "SecurityOpt": ["no-new-privileges:true"],
    "NetworkMode": "none"
  }
}
EOF
)

ID=$(
  api -X POST \
    -H "Content-Type: application/json" \
    --data "$BODY" \
    "$API/containers/create?name=$NAME" |
    json_field Id
)

if [[ -z "$ID" ]]; then
  echo "Container creation failed" >&2
  exit 1
fi

echo "[+] Created: $ID"

echo "[*] Starting container"
api -X POST "$API/containers/$ID/start"
echo

echo "[*] Inspecting container"
api "$API/containers/$ID/json" | node -e '
  let s="";
  process.stdin.on("data",d=>s+=d);
  process.stdin.on("end",()=>{
    const c=JSON.parse(s);
    console.log(JSON.stringify({
      ID:c.Id,
      State:c.State.Status,
      PID:c.State.Pid,
      Privileged:c.HostConfig.Privileged,
      Binds:c.HostConfig.Binds,
      NetworkMode:c.HostConfig.NetworkMode
    },null,2));
  });
'

echo
echo "Container ID: $ID"
echo "To stop:"
echo "curl --unix-socket $SOCK -X POST $API/containers/$ID/stop"
