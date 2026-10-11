#!/bin/sh
# detonate <npm|pypi> <filename> : runs /in/<filename>'s install and import steps under
# strace; traces go to /out. Every step has a hard timeout. Exit status is
# irrelevant: the traces are the result.
set -u
eco="$1"
art="/in/$2"
mkdir -p /tmp/pkg /tmp/site
# Bait: fake credentials in the tmpfs home. Built from pieces so no
# credential-shaped literal exists in source; none is valid anywhere.
b=SECOPSAIBAIT
mkdir -p "$HOME/.ssh" "$HOME/.aws" "$HOME/.config/gcloud"
printf '//registry.npmjs.org/:_authToken=%s_%snotarealtoken000000\n' npm "$b" > "$HOME/.npmrc"
printf '[pypi]\nusername = __token__\npassword = %s-%s-notarealtoken000000\n' pypi "$b" > "$HOME/.pypirc"
printf '[default]\naws_access_key_id = %s%s0000\naws_secret_access_key = %s/notarealsecret00000000000000\n' AK"IA" "$b" "$b" > "$HOME/.aws/credentials"
printf -- '-----%s %s PRIVATE KEY-----\n%s\n-----END %s PRIVATE KEY-----\n' BEGIN OPENSSH "$b" OPENSSH > "$HOME/.ssh/id_rsa"
printf '{"type":"service_account","private_key_id":"%s","client_email":"bait@%s.example"}\n' "$b" "$b" > "$HOME/.config/gcloud/application_default_credentials.json"
printf 'export GITHUB_TOKEN=%s_%snotarealtoken000\n' ghp "$b" > "$HOME/.bashrc"
chmod 600 "$HOME/.ssh/id_rsa"
# Loopback DNS recorder (nothing leaves: the container has no network).
python3 /usr/local/bin/dnslog.py /out/dns.log &
export NO_UPDATE_NOTIFIER=1 npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
STRACE="strace -f -tt -s 256 -x -e trace=execve,openat,connect,sendto,sendmsg,unlink,unlinkat,rename,renameat2,chmod,fchmodat"
step() { name="$1"; shift; timeout -s KILL "${STEP_TIMEOUT:-60}" $STRACE -o "/out/trace.$name" "$@" >"/out/stdout.$name" 2>&1; echo "$name exit=$?" >> /out/steps; }

case "$eco" in
  npm)
    tar -xzf "$art" -C /tmp/pkg 2>/out/extract.err
    cd /tmp/pkg/package 2>/dev/null || cd /tmp/pkg/* || exit 0
    for hook in preinstall install postinstall; do
      if node -e "process.exit(require('./package.json').scripts && require('./package.json').scripts['$hook'] ? 0 : 1)" 2>/dev/null; then
        step "$hook" npm run --ignore-scripts=false --offline "$hook"
      fi
    done
    step import node -e "try { require(process.cwd()) } catch (e) { console.error(e && e.message) }"
    ;;
  pypi)
    case "$(head -c 2 "$art" | od -An -tx1 | tr -d ' ')" in
      1f8b) tar -xzf "$art" -C /tmp/pkg 2>/out/extract.err; src="$(ls -d /tmp/pkg/*/ | head -1)"
            step install python3 -m pip install --no-deps --no-index --no-build-isolation --target /tmp/site "$src" ;;
      504b) step install python3 -m pip install --no-deps --no-index --target /tmp/site "$art" ;;
    esac
    for mod in $(ls /tmp/site 2>/dev/null | grep -v -e '\.dist-info$' -e '\.egg-info$' -e '^bin$' | sed 's/\.py$//' | head -5); do
      step "import-$mod" env PYTHONPATH=/tmp/site python3 -c "import $mod"
    done
    ;;
esac
exit 0
