#!/usr/bin/env bash
# Runner Boundary TUI v2.2 — evidence-oriented, no host takeover or persistence.
# Requires bash, Node.js 18, tar, coreutils; curl only for optional upload.
set -Eeuo pipefail
umask 077
BASE=${RBA_DIR:-"$PWD/runner-boundary-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
mkdir -p "$BASE"
BASE=$(cd "$BASE" && pwd -P)
REPORT="$BASE/evidence.txt"
SUMMARY="$BASE/summary.json"
HELPER="$BASE/docker-api-client.js"
SOCK=${DOCKER_SOCK:-/var/run/docker.sock}
UPLOAD_ENDPOINT=${RBA_UPLOAD_ENDPOINT:-https://ul.sto.care}
ARCHIVE=''
printf 'Runner Boundary TUI v2.2\nTimestamp UTC: %s\nOperating mode: diagnostics; no host filesystem writes or credential requests\n\n' "$(date -u +%FT%TZ)" > "$REPORT"
cat > "$HELPER" <<'NODE'
'use strict';
const http = require('http');
const fs = require('fs');
const socketPath = process.env.DOCKER_SOCK || '/var/run/docker.sock';
const mode = process.argv[2];
function request(method, path, body) {
  return new Promise((resolve,reject)=> {
    const req = http.request({socketPath,method,path,headers: body ? {'Content-Type':'application/json'} : {}}, res=> {
      let content=''; res.on('data', c=>{ content+=c; if(content.length>1_000_000) {req.destroy(new Error('Response too large'));}});
      res.on('end',()=>{ let json=null; try {json=JSON.parse(content);}catch{} resolve({status:res.statusCode,json,body:content});});
    });
    req.on('error',reject); req.setTimeout(5000,()=>req.destroy(new Error('Timeout')));
    req.end(body ? JSON.stringify(body) : undefined);
  });
}
const api='/v1.48';
function check(r,label) { if(r.status<200 || r.status>=300) throw Error(label+' returned HTTP '+r.status+' '+String(r.json?.message||'').slice(0,180)); return r.json; }
(async()=>{
 if(mode==='probe') {
   const ping=await request('GET','/_ping');
   const ver=await request('GET',api+'/version');
   const inf=await request('GET',api+'/info');
   console.log(JSON.stringify({socketAccessible:ping.status===200,pingStatus:ping.status,versionStatus:ver.status,apiVersion:ver.json?.ApiVersion||null,infoStatus:inf.status,rootless:inf.json?.SecurityOptions?.some(s=>s.includes('rootless'))||false,securityOptions:inf.json?.SecurityOptions||[],liveRestore:inf.json?.LiveRestoreEnabled??null},null,2));
   if(ping.status!==200) process.exitCode=1;
 } else if(mode==='containers') {
   const j=check(await request('GET',api+'/containers/json?all=true'),'containers');
   console.log(JSON.stringify(j.map(c=>({id:c.Id.slice(0,12),state:c.State,image:c.Image,labelsPresent:Object.keys(c.Labels||{}).length>0})),null,2));
 } else if(mode==='isolated-test') {
   // Confined, nonnetworked, no host binds, no privilege, and always remove on completion.
   const image=process.env.RBA_TEST_IMAGE || 'node:18-bullseye';
   const name='rba-probe-'+process.pid;
   const body={Image:image,Cmd:['/bin/sh','-c','sleep 25'],Tty:false,HostConfig:{Privileged:false,ReadonlyRootfs:true,CapDrop:['ALL'],NetworkMode:'none',Tmpfs:{'/tmp':'rw,nosuid,nodev,size=8m,mode=1777'},SecurityOpt:['no-new-privileges:true'],AutoRemove:false}};
   let id;
   try {
     id=check(await request('POST',api+'/containers/create?name='+encodeURIComponent(name),body),'create')?.Id;
     check(await request('POST',api+'/containers/'+id+'/start'),'start');
     const inspect=check(await request('GET',api+'/containers/'+id+'/json'),'inspect');
     const command=['/bin/sh','-c','id; uname -s; test -w /tmp && echo scratch_writable=yes || echo scratch_writable=no; printf RBA_TEST_OK > /tmp/rba-scratch-test; test "$(cat /tmp/rba-scratch-test)" = RBA_TEST_OK'];
     const exec=check(await request('POST',api+'/containers/'+id+'/exec',{AttachStdout:false,AttachStderr:false,Tty:false,Cmd:command}),'exec-create');
     check(await request('POST',api+'/exec/'+exec.Id+'/start',{Detach:true,Tty:false}),'exec-start');
     let result=null; for(let attempt=0;attempt<20;attempt++){result=check(await request('GET',api+'/exec/'+exec.Id+'/json'),'exec-inspect');if(!result.Running)break;await new Promise(resolve=>setTimeout(resolve,200));} if(result.Running || result.ExitCode!==0)throw Error('Isolated exec/scratch-volume write verification failed: '+JSON.stringify({running:result.Running,exitCode:result.ExitCode}));
     console.log(JSON.stringify({created:true,running:inspect.State?.Running,containerId:id.slice(0,12),privileged:inspect.HostConfig?.Privileged,binds:inspect.HostConfig?.Binds||[],networkMode:inspect.HostConfig?.NetworkMode,execStarted:true,execRunning:result.Running,execExitCode:result.ExitCode,scratchWriteVerified:true,scratchLocation:'container-only /tmp tmpfs',notes:'Command started inside a disposable unprivileged container, NOT in host namespaces.'},null,2));
   } finally {
     if (id) { try {const removed=await request('DELETE',api+'/containers/'+id+'?force=true&v=true'); console.error('Probe container cleanup HTTP '+removed.status);} catch(e) {console.error('WARNING: cleanup failed: '+e.message);} }
   }
 } else throw Error('Unknown mode');
})().catch(err=>{console.error('Docker API:',err.message);process.exitCode=1;});
NODE

header() { printf '\n===== %s =====\n' "$1" | tee -a "$REPORT"; }
record() { printf '\n$ %s\n' "$1" | tee -a "$REPORT"; shift; ("$@" 2>&1 || true) | tee -a "$REPORT"; }
identity() {
 header 'Identity';
 record 'date -u; id; uname -a' bash -c 'date -u; id; uname -a'
 record 'container and operating system' bash -c 'test -e /.dockerenv && echo dockerenv-present || echo dockerenv-absent; grep -E "^(PRETTY_NAME|VERSION_ID)=" /etc/os-release; printf "PID1: "; tr "\\0" " " </proc/1/cmdline; echo'
 record 'GitHub and runner environment variable NAMES (not values)' bash -c 'env | cut -d= -f1 | grep -E "^(GITHUB_|ACTIONS_|RUNNER_)" | LC_ALL=C sort || true'
}
security() {
 header 'Capabilities and security';
 record 'capability and seccomp status' bash -c 'grep -E "^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp|Seccomp_filters):" /proc/self/status'
 record 'namespace user mapping' bash -c 'cat /proc/self/uid_map /proc/self/gid_map'
 record 'AppArmor current profile' bash -c 'cat /proc/self/attr/current /proc/1/attr/current 2>/dev/null'
 record 'namespace identities' bash -c 'for f in /proc/self/ns/*; do readlink "$f" | sed "s|^|$(basename "$f") |"; done'
}
storage() {
 header 'Devices and mount metadata';
 record 'host block-device node metadata' bash -c 'ls -l /dev/sd* /dev/nvme* /dev/vd* 2>/dev/null || true'
 record 'block device listing (Debian 11 compatible)' bash -c 'command -v lsblk >/dev/null && lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT || true'
 record 'mount targets, source and ro/rw flags' bash -c 'findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | awk '\''{print $1, $2, $3, (($4 ~ /(^|,)ro(,|$)/) ? "ro" : "rw")} '\'' | head -n 75 || true'
 record 'Docker socket file metadata' bash -c 'for p in /run/docker.sock /var/run/docker.sock; do test -S "$p" && stat -c "%F mode=%a owner=%u:%g path=%n" "$p"; done; true'
}
cloud() {
 header 'Identity capabilities (presence only)';
 local n; for n in ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN AZURE_CLIENT_ID AWS_WEB_IDENTITY_TOKEN_FILE GOOGLE_APPLICATION_CREDENTIALS KUBERNETES_SERVICE_HOST; do
   if [[ -n ${!n-} ]]; then printf '%s: present\n' "$n"; else printf '%s: absent\n' "$n"; fi
 done | tee -a "$REPORT"
 printf 'No credential values recorded or identity tokens requested.\n' | tee -a "$REPORT"
}
docker_probe() { header 'Docker API probe (GET only)'; DOCKER_SOCK="$SOCK" record 'Docker daemon metadata' node "$HELPER" probe; }
docker_inventory() { header 'Container inventory (GET only)'; DOCKER_SOCK="$SOCK" record 'Docker containers (minimal fields)' node "$HELPER" containers; }
docker_test() {
 local noninteractive="${1:-false}"
 if [[ "$noninteractive" != true ]]; then
   printf 'Create, execute inside and remove a disposable isolated container, including its own /tmp write test? [y/N] '
   local ans
   read -r ans; [[ "$ans" =~ ^[yY]$ ]] || { printf 'SKIPPED: isolated container test declined\n' | tee -a "$REPORT"; return 0; }
 fi
 header 'Isolated container create/exec/scratch-write/cleanup test'
 DOCKER_SOCK="$SOCK" record 'Constrained container lifecycle and container-only tmpfs write test' node "$HELPER" isolated-test
}
host_boundary_checks() {
 header 'Host filesystem and namespace boundary checks (non-invasive)'
 printf '%s\n' \
  'HOST_ROOT_MOUNT: NOT EXECUTED - would introduce host filesystem access on a GitHub-hosted runner' \
  'HOST_ROOT_WRITE: NOT EXECUTED - would mutate GitHub-hosted runner filesystem' \
  'HOST_NAMESPACE_EXEC: NOT EXECUTED - no host namespace entry or host shell' \
  'Existing host-backed mounts and exposed block-device metadata are collected under Devices and mount metadata.' | tee -a "$REPORT"
}
kernel() { header 'Kernel inventory'; record 'kernel version and sysctl read-only data' bash -c 'uname -r; cat /proc/version; for p in /proc/sys/kernel/unprivileged_userns_clone /proc/sys/kernel/kptr_restrict; do test -r "$p" && { printf "%s=" "$p"; cat "$p"; }; done; true'; }
all_checks() { identity; security; storage; cloud; docker_probe; docker_inventory; kernel; docker_test true; host_boundary_checks; }
summary() {
 RBA_REPORT="$REPORT" RBA_SUMMARY="$SUMMARY" node - <<'NODE'
const fs=require('fs');
const t=fs.readFileSync(process.env.RBA_REPORT,'utf8');
const get = re => t.match(re)?.[1] || null;
const s={generatedUTC:new Date().toISOString(),reportVersion:'2.2',evidenceMode:'diagnostics',uid:get(/uid=(\d+)/),effectiveCapabilities:get(/CapEff:\s*([a-f\d]+)/i),seccomp:get(/Seccomp:\s*(\d+)/),apparmorUnconfined:t.includes('unconfined'),dockerSocketReachable:t.includes('"socketAccessible": true'),oidcRequestEnvPresent:t.includes('ACTIONS_ID_TOKEN_REQUEST_TOKEN: present'),isolatedContainerExec:t.includes('\"execStarted\": true')?'confirmed':'not confirmed',isolatedScratchWrite:t.includes('\"scratchWriteVerified\": true')?'confirmed':'not confirmed',hostRootMount:'NOT EXECUTED',hostWriteTest:'NOT EXECUTED',hostNamespaceExec:'NOT EXECUTED',credentialExtraction:'not performed',crossRunnerAccess:'not tested',crossJobPersistence:'not tested'};
fs.writeFileSync(process.env.RBA_SUMMARY,JSON.stringify(s,null,2)+'\n');
console.log(JSON.stringify(s,null,2));
NODE
}
bundle() {
 summary | tee -a "$REPORT"
 local parent name
 parent=$(dirname "$BASE"); name=$(basename "$BASE")
 # Only trusted generated filenames are included. No home directory or host files.
 ARCHIVE="$parent/${name}.tar.gz"
 tar -C "$BASE" -czf "$ARCHIVE" evidence.txt summary.json docker-api-client.js
 printf '\nArchive: %s\n' "$ARCHIVE"
 printf 'SHA256: '; sha256sum "$ARCHIVE"
}
upload() {
 local noninteractive="${1:-false}"
 if [[ ! -f "$SUMMARY" ]]; then bundle; fi
 [[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || { echo 'Create archive first (menu 9).'; return; }
 if ! command -v curl >/dev/null; then echo 'curl unavailable'; return; fi
 if [[ "$noninteractive" != true ]]; then
   printf 'Upload evidence archive to %s? This transfers data to a THIRD PARTY. [y/N] ' "$UPLOAD_ENDPOINT"
   local reply
   read -r reply; [[ "$reply" =~ ^[yY]$ ]] || return 0
 else
   printf 'Explicit --upload flag supplied; transferring allowlisted diagnostic archive to %s\n' "$UPLOAD_ENDPOINT"
 fi
 local response status
 response=$(mktemp); status=$(curl --silent --show-error --max-time 90 -o "$response" -w '%{http_code}' -F "file=@${ARCHIVE}" "$UPLOAD_ENDPOINT") || { echo 'Upload failed'; rm -f "$response"; return 1; }
 printf 'Upload HTTP status: %s\n' "$status"
 if [[ "$status" =~ ^2 ]]; then
   # Show a URL only if explicitly supplied by the service response.
   node - "$response" <<'NODE'
const fs=require('fs');
const body=fs.readFileSync(process.argv[2],'utf8');
let candidates=body.match(/https:\/\/[^\s"'<>]+/g)||[];
try {const j=JSON.parse(body);for(const v of [j.url,j.link,j.download_url,j.data?.url])if(typeof v==='string')candidates.unshift(v);}catch{}
const valid=candidates.find(u=>{try{const x=new URL(u);return x.protocol==='https:'&&(x.hostname==='ul.sto.care'||x.hostname.endsWith('.sto.care'));}catch{return false;}});
if(valid)console.log('Uploaded file URL: '+valid);
else console.log('Upload succeeded, but no validated sto.care file URL was returned. Response excerpt: '+body.slice(0,500));
NODE
 else echo "Upload unsuccessful; server response (first 300 bytes):"; head -c 300 "$response"; echo; fi
 rm -f "$response"
 [[ "$status" =~ ^2 ]]
}
usage() { echo 'Usage: bash runner-boundary-tui.sh [--all [--upload] | --bundle | --help]'; }
case ${1:-} in
 --help) usage; exit 0;;
 --all)
   if [[ ${2:-} == --upload && $# -eq 2 ]]; then
     all_checks; bundle; upload true; exit $?
   elif [[ $# -eq 1 ]]; then
     all_checks; bundle; exit 0
   else
     usage; exit 2
   fi;;
 --bundle) all_checks; bundle; exit 0;;
 '') ;;
 *) usage; exit 2;;
esac
while :; do
 cat <<'MENU'

=== Runner Boundary TUI v2.2 ===
 1  Identity and environment variable names
 2  Capabilities, AppArmor, seccomp, namespaces
 3  Devices, mounts, socket metadata
 4  Docker daemon probe (GET only)
 5  Docker containers inventory (GET only)
 6  Isolated container create/exec/scratch-write/cleanup (opt-in)
 7  OIDC presence and kernel inventory
 8  Run ALL checks (including isolated container test)
 9  Bundle evidence into tar.gz + SHA256
10  Upload archive to ul.sto.care (opt-in)
 0  Exit
MENU
 printf 'Choice: '; read -r choice || break
 case $choice in
 1) identity;;2) security;;3) storage;;4) docker_probe;;5) docker_inventory;;6) docker_test;;
 7) cloud; kernel;;8) all_checks;;9) bundle;;10) upload;;0) break;;*) echo 'Invalid choice';;
 esac
done
printf 'Evidence directory: %s\n' "$BASE"
