#!/usr/bin/env bash
# Runner Boundary Audit: read-only collection for container security research.
# Compatible with Debian-based node:18-bullseye; no package installs required.
set -u
umask 077
OUT=${RBA_OUT:-"${PWD}/runner-boundary-$(date -u +%Y%m%dT%H%M%SZ).txt"}
if ! ( : >> "$OUT" ) 2>/dev/null; then OUT="/tmp/runner-boundary-$(date -u +%Y%m%dT%H%M%SZ).txt"; fi
printf 'Runner Boundary Audit | UTC %s\n' "$(date -u +%FT%TZ)" >> "$OUT"
printf 'Mode: read-only; sensitive environment values deliberately excluded\n\n' >> "$OUT"
section() { printf '\n===== %s =====\n' "$1"; }
run() { printf '\n$ %s\n' "$1"; bash -c "$1" 2>&1 || :; }
record() { local tmp; tmp=$(mktemp); "$@" > "$tmp" 2>&1 || :; cat "$tmp" | tee -a "$OUT"; rm -f "$tmp"; }
identity() {
 section 'Container and runner identity'
 run 'date -u; id; uname -a'
 run 'test -e /.dockerenv && echo dockerenv-present || echo dockerenv-absent'
 run 'cat /proc/1/cgroup'
 run 'printf "PID 1: "; tr "\\0" " " </proc/1/cmdline; echo'
 run 'printf "OS: "; grep -E "^(PRETTY_NAME|VERSION_ID)=" /etc/os-release || true'
 run 'printf "Runner context variable names (values hidden): "; env | cut -d= -f1 | grep -E "^(GITHUB_|ACTIONS_|RUNNER_)" | LC_ALL=C sort | paste -sd, -'
}
capabilities() {
 section 'Capabilities and security restrictions'
 run 'grep -E "^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp|Seccomp_filters):" /proc/self/status'
 run 'if command -v capsh >/dev/null; then capsh --print; else echo "capsh unavailable; hexadecimal masks shown above"; fi'
 run 'cat /proc/self/uid_map /proc/self/gid_map'
 run 'for x in /proc/self/attr/current /proc/1/attr/current; do if [ -r "$x" ]; then printf "%s: " "$x"; cat "$x"; fi; done'
 # CAP_SYS_ADMIN = bit 21, CAP_SYS_PTRACE = bit 19, CAP_DAC_READ_SEARCH = bit 2.
 local mask; mask=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
 if [[ $mask =~ ^[a-fA-F0-9]+$ ]]; then
   printf 'Effective capability signals: SYS_ADMIN=%s SYS_PTRACE=%s DAC_READ_SEARCH=%s\n' \
     "$(( (16#$mask & (1<<21)) != 0 ))" "$(( (16#$mask & (1<<19)) != 0 ))" "$(( (16#$mask & (1<<2)) != 0 ))"
 fi
}
namespaces() {
 section 'Namespace and isolation information'
 run 'ls -l /proc/self/ns /proc/1/ns'
 run 'cat /proc/self/mountinfo | head -n 35'
 run 'grep -E "^(NSpid|NStgid|NSpgid|NSsid):" /proc/self/status'
}
mounts() {
 section 'Device exposure and bind-mount review'
 run 'ls -l /dev/sd* /dev/vd* /dev/nvme* /dev/mapper/* 2>/dev/null || true'
 run 'command -v lsblk >/dev/null && lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS || echo "lsblk unavailable"'
 run 'command -v findmnt >/dev/null && findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS || cat /proc/mounts'
 run 'for p in /var/run/docker.sock /run/docker.sock /host /mnt/host /__w /__t /github/home; do if test -e "$p"; then stat -c "%F %a %u:%g %n" "$p"; fi; done'
}
docker_socket() {
 section 'Docker socket read-only probe'
 if [[ ! -S /var/run/docker.sock ]]; then echo 'No Unix Docker socket at /var/run/docker.sock'; return; fi
 stat -c '%F permissions=%a owner=%u:%g path=%n' /var/run/docker.sock
 if ! command -v node >/dev/null; then echo 'Node unavailable; no socket requests sent'; return; fi
 # Only read-only Docker API GET endpoints. No container enumeration or secrets.
 node - <<'JS'
const http=require('http');
const socketPath='/var/run/docker.sock';
for(const path of ['/_ping','/version','/info']){
 const req=http.get({socketPath,path,timeout:3000},res=>{
  let data='';res.on('data',d=>data+=d);res.on('end',()=>{
   console.log(`${path}: HTTP ${res.statusCode}`);
   if(path==='/version'){
    try { const v=JSON.parse(data); console.log(` Engine API=${v.ApiVersion||'?'} OS=${v.Os||'?'} Arch=${v.Arch||'?'}`); }catch{}
   }
   if(path==='/info'){
    try {const v=JSON.parse(data); console.log(` SecurityOptions=${JSON.stringify(v.SecurityOptions||[])} Rootless=${Boolean(v.Rootless)} LiveRestore=${Boolean(v.LiveRestoreEnabled)}`)}catch{}
   }
  });
 });
 req.on('timeout',()=>req.destroy(new Error('timeout')));
 req.on('error',e=>console.log(`${path}: ${e.code||e.message}`));
}
JS
}
cloud() {
 section 'Cloud and Kubernetes credential-presence checks (no values or requests)'
 for name in ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN AZURE_CLIENT_ID AWS_WEB_IDENTITY_TOKEN_FILE GOOGLE_APPLICATION_CREDENTIALS KUBERNETES_SERVICE_HOST; do
  if [[ -v $name ]]; then echo "$name: present"; else echo "$name: absent"; fi
 done
 for p in /var/run/secrets/kubernetes.io/serviceaccount/token /var/run/secrets/kubernetes.io/serviceaccount/namespace; do
  if [[ -e $p ]]; then echo "$(basename "$p"): present"; else echo "$(basename "$p"): absent"; fi
 done
 echo 'No token values displayed; no metadata endpoints accessed; no OIDC token requested.'
}
kernel() {
 section 'Kernel and runtime inventory (no exploit execution)'
 run 'uname -r; cat /proc/version'
 run 'grep -E "^(CONFIG_(USER_NS|SECCOMP|SECCOMP_FILTER|BPF|OVERLAY_FS|CGROUPS))=" /boot/config-$(uname -r) 2>/dev/null || echo "Kernel build config unavailable"'
 run 'test -r /proc/sys/kernel/unprivileged_userns_clone && cat /proc/sys/kernel/unprivileged_userns_clone || true'
 run 'test -r /proc/sys/kernel/kptr_restrict && cat /proc/sys/kernel/kptr_restrict || true'
 echo 'Kernel version is inventory only, not a vulnerability determination.'
}
all() { identity; capabilities; namespaces; mounts; docker_socket; cloud; kernel; }
menu() {
 while :; do
  printf '\n=== Runner Boundary Audit (read-only) ===\n'
  printf '1 Identity / cgroups\n2 Capabilities / seccomp\n3 Namespaces\n4 Devices / mounts\n5 Docker socket (GET only)\n6 OIDC / Kubernetes presence (no secrets)\n7 Kernel inventory\n8 Run all and save evidence\n0 Exit\n'
  printf 'Evidence: %s\nChoice: ' "$OUT"
  read -r choice || break
  case "$choice" in
   1) record identity;; 2) record capabilities;; 3) record namespaces;;
   4) record mounts;; 5) record docker_socket;; 6) record cloud;;
   7) record kernel;; 8) record all;; 0) break;; *) echo 'Invalid selection';;
  esac
 done
}
case "${1:-}" in
 --all) record all;; --help|-h) echo "Usage: bash $0 [--all|--help] (default: interactive menu)";; *) menu;;
esac
printf '\nEvidence saved to %s\n' "$OUT"
