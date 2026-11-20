#!/usr/bin/env bash
# Push HEAD to main with the blog publish deploy key.
#
# main requires pull requests and passing checks. GitHub does not let a
# personal repository exempt the built-in Actions token from that rule, so
# the blog publishers push with a write deploy key instead; deploy keys are
# the only ruleset bypass actor. The key lives in the
# BLOG_PUBLISH_DEPLOY_KEY secret and never touches disk outside RUNNER_TEMP.
set -euo pipefail
: "${BLOG_PUBLISH_DEPLOY_KEY:?BLOG_PUBLISH_DEPLOY_KEY secret is not set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"

dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/push-main.XXXXXX")"
trap 'rm -rf "$dir"' EXIT
umask 077
printf '%s\n' "$BLOG_PUBLISH_DEPLOY_KEY" > "$dir/key"
# GitHub's published SSH host key (https://api.github.com/meta, ssh_keys).
echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" > "$dir/known_hosts"

GIT_SSH_COMMAND="ssh -i $dir/key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$dir/known_hosts" \
  git push "git@github.com:${GITHUB_REPOSITORY}.git" HEAD:main
