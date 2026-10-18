# shellcheck shell=bash
# Shared Bash helpers for commands sent through an SSH USB host.
# Source this file, set BRIDGE and SERIAL, then call adb_host_validate.

adb_host_validate() {
  # Restrict destinations to SSH aliases, hostnames or IPv4, optionally user@host.
  # Serial numbers may also use adb's host:port syntax.
  if [[ ! "$BRIDGE" =~ ^([A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]]; then
    echo 'invalid BRIDGE: use a hostname or SSH alias, optionally user@host' >&2
    return 2
  fi
  if [[ ! "$SERIAL" =~ ^[A-Za-z0-9_][A-Za-z0-9_.:-]*$ ]]; then
    echo 'invalid SERIAL' >&2
    return 2
  fi
}

adb_host_quote() {
  # POSIX shell quoting: the bridge need not use Bash as its login shell.
  local value=${1//\'/\'\\\'\'}
  printf "'%s'" "$value"
}

adb_host() {
  local command argument
  command="adb -s $(adb_host_quote "$SERIAL")"
  for argument in "$@"; do
    command+=" $(adb_host_quote "$argument")"
  done
  ssh -- "$BRIDGE" "$command"
}

adb_host_optional() {
  # Handle missing diagnostics on Android; never mask an SSH transport failure.
  adb_host shell "{ $1; } || { echo 'optional diagnostic unavailable' >&2; :; }"
}
