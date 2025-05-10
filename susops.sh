#!/usr/bin/env bash

susops() {
  # Disable job control PID output
  set +m

  # Defaults
  local -r workspace="${SUSOPS_WORKSPACE:-$HOME/.susops}"

  # Define file paths for storing ports and config
  local -r ssh_hostfile="$workspace/ssh_host"
  local -r socks_portfile="$workspace/socks_port"
  local -r pac_portfile="$workspace/pac_port"
  local -r pacfile="$workspace/susops.pac"
  local -r remote_conf="$workspace/remote.conf"
  local -r local_conf="$workspace/local.conf"

  # Define process names for easier identification
  local -r SUSOPS_SSH_PROCESS_NAME="susops-ssh"
  local -r SUSOPS_PAC_LOOP_PROCESS_NAME="susops-pac-loop"
  local -r SUSOPS_PAC_NC_PROCESS_NAME="susops-pac-nc"
  local -r SUSOPS_PAC_UNIFIED_PROCESS_NAME="susops-pac"

  # Verbosity toggle for debugging
  local verbose=false

  mkdir -p "$workspace"

  # Parse global flags
  local args=()
  for arg in "$@"; do
    case "$arg" in
      -v|--verbose) verbose=true ;;
      *) args+=("$arg") ;;
    esac
  done
  set -- "${args[@]}"  # Reset positional parameters

  # Ensure at least one sub-command is provided
  [[ $1 ]] || { susops help; return 1; }
  local cmd=$1; shift

  # Helper: load or generate a random ephemeral port and persist it
  load_port() {
    local file="$1"
    if [[ -f "$file" ]]; then
      cat "$file"
    else
      # zsh always returns the same $RANDOM value in subshells
      # see https://github.com/bminor/bash/blob/f3a35a2d601a55f337f8ca02a541f8c033682247/variables.c#L1371
      # Workaround: read 2 bytes from /dev/random, convert to integer, map to dynamic port range
      local raw port
      raw=$(head -c2 /dev/random | od -An -tu2 | tr -d ' ')
      port=$(( raw % 16384 + 49152 ))
      echo "$port" > "$file"
      echo "$port"
    fi
  }

  # Load (or generate) SOCKS and PAC ports
  local ssh_host=""
  if [[ -f "$ssh_hostfile" ]]; then
    ssh_host=$(<"$ssh_hostfile")
  fi
  local socks_port pac_port
  socks_port=$(load_port "$socks_portfile")
  pac_port=$(load_port "$pac_portfile")

  # Create basic PAC file if missing
  [[ -f "$pacfile" ]] || cat > "$pacfile" << 'EOF'
function FindProxyForURL(url, host) {
  return "DIRECT";
}
EOF

  align_printf() {
    local format=$1; shift
    local args=("$@")
    printf "%-13s $format\n" "${args[@]}"
  }

  # Helper: check if a service is running based on PID file
  is_running() {
    local proc_name="$1"
    local description="${2:-Service}"
    local print_flag="$3"
    local port="$4"
    local additional="$5"

    # find exact-match PIDs (newline-separated)
    pids=$(pgrep -a -- "$proc_name" 2>/dev/null || :)

    if [ -n "$pids" ]; then
      pid_list=$(printf "%s" "$pids" | tr '\n' ' ' | sed 's/ $//')
      count=$(wc -w <<< "$pid_list")
      if [ "$count" -gt 1 ]; then
        pid_string="PIDs $pid_list"
      else
        pid_string="PID $pid_list"
      fi

      # print if requested
      if [ "$print_flag" = true ]; then
        if [ -n "$additional" ]; then
          align_printf "✅ running (%s, port %s, %s)" "$description:" "$pid_string" "$port" "$additional"
        else
          align_printf "✅ running (%s, port %s)" "$description:" "$pid_string" "$port"
        fi
      fi
      return 0
    fi

    # not running
    [ "$print_flag" = true ] && align_printf "⚠️ not running" "$description:"
    return 1
  }


  test_entry() {
    local target=$1
    if [[ ! $target =~ ^[0-9]+$ ]]; then
      if curl -s -k --max-time 5 --proxy socks5h://127.0.0.1:"$socks_port" "https://$target" >/dev/null 2>&1; then
        printf "✅ %s via SOCKS\n" "$target"; return 0
      else
        printf "❌ %s via SOCKS\n" "$target"; return 1
      fi
    else
      if [[ -f $local_conf ]] && grep -q "^$target " "$local_conf" 2>/dev/null; then
        local rp=$(awk '$1==n{print $2}' n="$target" "$local_conf")
        if curl -s --max-time 5 "http://localhost:$target" >/dev/null 2>&1; then
          printf "✅ local:%s -> $ssh_host:%s\n" "$target" "$rp"; return 0
        else
          printf "❌ local:%s -> $ssh_host:%s\n" "$target" "$rp"; return 1
        fi
      elif [[ -f $remote_conf ]] && grep -q "^$target " "$remote_conf" 2>/dev/null; then
        local lp=$(awk '$1==n{print $2}' n="$target" "$remote_conf")
        if ssh "$ssh_host" curl -s --max-time 5 "http://localhost:$target" >/dev/null 2>&1; then
          printf "✅ $ssh_host:%s -> localhost:%s\n" "$target" "$lp"; return 0
        else
          printf "❌ $ssh_host:%s -> localhost:%s\n" "$target" "$lp"; return 1
        fi
      else
        printf "❌ Port %s not found in local or remote config\n" "$target"; return 1
      fi
    fi
  }

  stop_by_name() {
    local proc_name="$1"
    local label="$2"
    local keep_ports="${3:-false}"
    local pids

    # find every exact-match PID
    pids=$(pgrep -a -- "$proc_name")

    if [ -n "$pids" ]; then
      # kill any that are still alive
      for pid in $pids; do
        if kill -0 "$pid" 2>/dev/null; then
          kill "$pid" 2>/dev/null
        fi
      done

      # clean up port file unless keep_ports is true
      ! $keep_ports && rm -f "$socks_portfile"

      align_printf "🛑 stopped" "$label"
    else
      ! $keep_ports && align_printf "⚠️ not running" "$label"
    fi
  }

  validate_port_in_range() {
    # $1: port
    [[ $1 =~ ^[0-9]+$ && $1 -ge 1 && $1 -le 65535 ]]
  }

  # Generic checks against a config file
  check_exact_rule() {
    # $1: src port, $2: dst port, $3: config file
    grep -q "^${1} ${2}$" "$3" 2>/dev/null
  }

  check_port_source() {
    # $1: port, $2: config file
    grep -q "^${1} " "$2" 2>/dev/null
  }

  check_port_target() {
    # $1: port, $2: config file
    grep -q "^[0-9]\+ ${1}$" "$2" 2>/dev/null
  }

  # Check if a port is in use on localhost or remote host
  check_port_in_use() {
    # $1: port, $2 (optional): host (defaults to localhost)
    local port=$1 host=${2:-localhost}
    if [[ "$host" == localhost ]]; then
      lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1
    else
      ssh "$host" lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1
    fi
  }

  case $cmd in
    help|--help|-h)
      cat << EOF
Usage: susops [-v|--verbose] COMMAND [ARGS]
Commands: .
  add [-l LOCAL_PORT REMOTE_PORT] [-r REMOTE_PORT LOCAL_PORT] [HOST]  add hostname or port forward, schema source → target
  rm  [-l LOCAL_PORT]             [-r REMOTE_PORT]            [HOST]  remove hostname or port forward
  start [ssh_host] [socks_port] [pac_port]                            start proxy and PAC server
  stop  [--keep-ports]                                                stop proxy and server
  restart                                                             stop and start (preserves ports)
  ls                                                                  list PAC hosts and remote forwards
  ps                                                                  show status, ports, and remote forwards
  reset [--force]                                                     remove all files and configs
  test  (--all|TARGET)                                                test connectivity
  chrome                                                              launch Chrome with proxy
  chrome-proxy-settings                                               open Chrome proxy settings
  firefox                                                             launch Firefox with proxy
  help|--help|-h                                                      show this help message
Options:
  -v, --verbose                                                       enable verbose output
EOF
      ;;

    add)
      case "$1" in
        -l)
          local lport=$2 rport=$3
          [[ $lport && $rport ]] || {
            echo "Usage: susops add -l REMOTE_PORT LOCAL_PORT"
            echo "Map a port from a remote server to your localhost"
            return 1
          }

          if ! validate_port_in_range "$lport"; then
            echo "LOCAL_PORT must be a valid port in range 1 to 65535"
            return 1
          elif ! validate_port_in_range "$rport"; then
            echo "REMOTE_PORT must be a valid port in range 1 to 65535"
            return 1
          elif check_exact_rule "$lport" "$rport" "$local_conf"; then
            echo "Local forward localhost:${lport} → $ssh_host:${rport} is already registered"
            return 1
          elif check_port_source "$lport" "$local_conf"; then
            echo "Local port ${lport} is already the source of a local forward"
            return 1
          elif check_port_target "$lport" "$remote_conf"; then
            echo "Local port ${lport} is already the target of a remote forward"
            return 1
          elif check_port_source "$rport" "$remote_conf"; then
            echo "Remote port ${rport} is already the source of a remote forward"
            return 1
          elif check_port_in_use "$lport"; then
            echo "Local port $lport is already in use on localhost"
            return 1
          else
            echo "${lport} ${rport}" >> "$local_conf"
            echo "Registered local forward localhost:${lport} → $ssh_host:${rport}"
            is_running "$SUSOPS_SSH_PROCESS_NAME" && echo "Restart proxy to apply"
            return 0
          fi
          ;;

        -r)
          local rport=$2 lport=$3
          [[ $rport && $lport ]] || {
            echo "Usage: susops add -r LOCAL_PORT REMOTE_PORT"
            echo "Map a port from your localhost to a remote server"
            return 1
          }

          if ! validate_port_in_range "$rport"; then
            echo "REMOTE_PORT must be a valid port in range 1 to 65535"
            return 1
          elif ! validate_port_in_range "$lport"; then
            echo "LOCAL_PORT must be a valid port in range 1 to 65535"
            return 1
          elif check_exact_rule "$rport" "$lport" "$remote_conf"; then
            echo "Remote forward $ssh_host:${rport} → localhost:${lport} is already registered"
            return 1
          elif check_port_source "$rport" "$remote_conf"; then
            echo "Remote port ${rport} is already the source of a remote forward"
            return 1
          elif check_port_target "$rport" "$local_conf"; then
            echo "Remote port ${rport} is already the target of a local forward"
            return 1
          elif check_port_source "$lport" "$local_conf"; then
            echo "Local port ${lport} is already the source of a local forward"
            return 1
          elif check_port_in_use "$rport" "$ssh_host"; then
            echo "Remote port $rport is already in use on $ssh_host"
            return 1
          else
            echo "${rport} ${lport}" >> "$remote_conf"
            echo "Registered remote forward $ssh_host:${rport} → localhost:${lport}"
            is_running "$SUSOPS_SSH_PROCESS_NAME" && echo "Restart proxy to apply"
            return 0
          fi
          ;;

        *)
          local host=$1
          [[ $host ]] || {
            echo "Usage: add [HOST] [-l REMOTE_PORT LOCAL_PORT] [-r LOCAL_PORT REMOTE_PORT]";
            echo "Ports are mapped in schema FROM -> TO";
            return 1;
          }

          if grep -q "host === \"$host\"" "$pacfile"; then
            echo "$host is already in PAC file"
            return 1
          fi

          host=$(echo "$host" | sed -E 's/^[^:]+:\/\///; s/\/.*//')

          awk -v h="$host" '/return "DIRECT"/ { print "  if (host === \""h"\" || dnsDomainIs(host, \"."h"\")) return \"SOCKS5 127.0.0.1:'$socks_port'\";" }1' \
            "$pacfile" > "$workspace/tmp.pac" && mv "$workspace/tmp.pac" "$pacfile"

          echo "Added $host to PAC file"
          is_running "$SUSOPS_SSH_PROCESS_NAME" "SOCKS5 proxy" && test_entry "$host"
          return 0
      esac
      ;;

    rm)
      case "$1" in
        -l)
          local lport=$2
          [[ $lport ]] || { echo "Usage: susops rm -l LOCAL_PORT"; return 1; }
          if grep -q "^$lport " "$local_conf" 2>/dev/null; then
            sed -i '' "/^$lport /d" "$local_conf"
            echo "Removed local forward localhost:$lport"
            is_running "$SUSOPS_SSH_PROCESS_NAME" && echo "Restart proxy to apply"
            return 0
          else
            echo "No local forward for localhost:$lport"
            return 1
          fi
          ;;

        -r)
          local rport=$2
          [[ $rport ]] || { echo "Usage: susops rm -r REMOTE_PORT"; return 1; }
          if grep -q "^$rport " "$remote_conf" 2>/dev/null; then
            sed -i '' "/^$rport /d" "$remote_conf"
            echo "Removed remote forward $ssh_host:$rport"
            is_running "$SUSOPS_SSH_PROCESS_NAME" && echo "Restart proxy to apply"
            return 0
          else
            echo "No remote forward for $ssh_host:$rport"
            return 1
          fi
          ;;

        *)
          local host=$1
          [[ $host ]] || { echo "Usage: rm [HOST] [-l LOCAL_PORT] [-r REMOTE_PORT]"; return 1; }
          if grep -q "host === \"$host\"" "$pacfile"; then
            sed -i '' "/host === \"$host\"/d" "$pacfile"
            echo "Removed $host from PAC file"
            is_running "$SUSOPS_SSH_PROCESS_NAME" && echo "Restart proxy to apply"
            return 0
          else
            echo "$host not found in PAC file"
            if [[ $host =~ ^[0-9]+$ ]]; then echo "Use \"susops -l LOCAL_PORT\" OR \"susops -r REMOTE_PORT\" to remove a forwarded port"; fi
            return 1
          fi
          ;;
      esac
      ;;

    restart)
      susops stop --keep-ports
      susops start
      ;;

    start)
      [[ $1 ]] && ssh_host=$1 && echo "$ssh_host" > "$ssh_hostfile"
      [[ $2 ]] && socks_port=$2 && echo "$socks_port" > "$socks_portfile"
      [[ $3 ]] && pac_port=$3 && echo "$pac_port" > "$pac_portfile"
      sed -E -i '' "s#(SOCKS5 127\\.0\\.0\\.1:)[0-9]+#\\1$socks_port#g" "$pacfile"

      if [[ -z $ssh_host ]]; then
        echo "SSH host is empty, please set as argument"
        return 1
      fi

      # Only start SOCKS proxy if not already running
      if pgrep -f "$SUSOPS_SSH_PROCESS_NAME" >/dev/null; then
        is_running "$SUSOPS_SSH_PROCESS_NAME" "SOCKS5 proxy" true "$socks_port"
      else
        # Build local forward arguments
        local local_args=()
        [[ -f "$local_conf" ]] && while read -r lp rp; do local_args+=("-L" "${lp}:localhost:${rp}"); done < "$local_conf"
        # Build remote tunnel arguments
        local remote_args=()
        [[ -f "$remote_conf" ]] && while read -r rp lp; do remote_args+=("-R" "${rp}:localhost:${lp}"); done < "$remote_conf"

        # Build SSH command
        local ssh_cmd=( autossh -M 0 -N -T -D "$socks_port" "${local_args[@]}" "${remote_args[@]}" "$ssh_host" )
        if ! command -v autossh >/dev/null 2>&1; then
          $verbose && echo "autossh not found, falling back to ssh"
          ssh_cmd=( ssh -N -T -D "$socks_port" "${local_args[@]}" "${remote_args[@]}" "$ssh_host" )
        fi

        $verbose && printf "Full SSH command: %s\n" "nohup bash -c 'exec -a $SUSOPS_SSH_PROCESS_NAME ${ssh_cmd[*]}' </dev/null >/dev/null 2>&1 &"
        nohup bash -c "exec -a $SUSOPS_SSH_PROCESS_NAME ${ssh_cmd[*]}" </dev/null >/dev/null 2>&1 &

        align_printf "🚀 started (PID %s, port %s)" "SOCKS5 proxy:" "$!" "$socks_port"
      fi

      # Only start PAC server if not already running
      if pgrep -a "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" >/dev/null; then
        is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" "PAC server" true "$pac_port" "URL: http://localhost:$pac_port/susops.pac"
      else
        length=$(wc -c <"$pacfile")
        nohup bash -c "exec -a $SUSOPS_PAC_LOOP_PROCESS_NAME bash -c \"while true; do
            {
              printf 'HTTP/1.1 200 OK\r\n'
              printf 'Content-Type: application/x-ns-proxy-autoconfig\r\n'
              printf 'Content-Length: %s\r\n' $length
              printf 'Connection: close\r\n'
              printf '\r\n'
              cat \\\"$pacfile\\\"
            } | exec -a $SUSOPS_PAC_NC_PROCESS_NAME nc -l $pac_port
        done\"" </dev/null >/dev/null 2>&1 &

        local pac_pid=$!

        # ensure
        local max_wait=5
        local interval=0.1
        steps=$(printf "%.0f" "$(echo "$max_wait / $interval" | bc -l)")  # workaround, $i has to be an integer value
        for ((i=0; i<steps; i++)); do
          if nc_pid=$(pgrep -f "$SUSOPS_PAC_NC_PROCESS_NAME"); then
            align_printf "🚀 started (PIDs %s & %s, port %s, URL %s)" "PAC server:" "$pac_pid" "$nc_pid" "$pac_port" "http://localhost:$pac_port/susops.pac"
            break
          fi
          $verbose && printf "Waiting for PAC server to start... (%d/%d)\n" $((i + 1)) "$steps"
          sleep "$interval"
        done
        if [[ $i -ge $steps ]]; then
          align_printf "⚠️ partially started (PID %s, port %s, URL %s)" "PAC server:" "$pac_pid" "$pac_port" "http://localhost:$pac_port/susops.pac"
          return 1
        fi
      fi
      ;;

    stop)
      local keep_ports=false
      [[ $1 == '--keep-ports' ]] && keep_ports=true
      stop_by_name "$SUSOPS_SSH_PROCESS_NAME" "SOCKS5 proxy:" $keep_ports
      stop_by_name "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" "PAC server:" $keep_ports
      return 0
      ;;

    ls)
      echo "PAC hosts:"
      if grep -q 'host ===' "$pacfile"; then
        sed -E -n 's/.*host === "([^"]+)".*/→ \1/p' "$pacfile"
      else
        echo "- None"
      fi
      echo "Local forwards:"
      if [[ -s "$local_conf" ]]; then
        while read -r lp rp; do echo "- localhost:$lp → $ssh_host:$rp"; done < "$local_conf"
      else
        echo "- None"
      fi
      echo "Remote forwards:"
      if [[ -s "$remote_conf" ]]; then
        while read -r rp lp; do echo "- $ssh_host:$rp → localhost:$lp"; done < "$remote_conf"
      else
        echo "- None"
      fi
      ;;

    ps)
      is_running "$SUSOPS_SSH_PROCESS_NAME" "SOCKS5 proxy" true "$socks_port"
      result_socks=$?
      is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" "PAC server" true "$pac_port" "URL: http://localhost:$pac_port/susops.pac"
      result_pac=$?
      return $(( result_socks + result_pac ))
      ;;

    reset)
      force=false
      if [[ "$1" == "--force" ]]; then
        force=true
      fi

      if ! $force; then
        echo "This will stop susops and remove all of its configs"
        printf "Are you sure? [y/N] "
        read -r user_decision
        if [[ ! $user_decision =~ ^[Yy]$ ]]; then
          return 1
        fi
      fi

      susops stop --keep-ports #--keep-ports is used to not show stop hints
      rm -rf "$workspace"
      echo "Removed all files and configs"
      ;;

    test)
      [[ $1 ]] || { echo "Usage: susops test (--all|TARGET)"; return 1; }
      is_running "$SUSOPS_SSH_PROCESS_NAME" "SOCKS5 proxy" || { align_printf "⚠️ not running, use \"susops start\" first" "SOCKS5 proxy:"; return 1; }
      if [[ $1 == --all ]]; then
        sed -n 's/.*host === "\([^"]*\)".*/\1/p' "$pacfile" | while read -r d; do test_entry "$d"; done

        if [[ -f "$local_conf" ]]; then
          for p in $(awk '{print $1}' "$local_conf"); do
            test_entry "$p" || true
          done
        fi

        if [[ -f "$remote_conf" ]]; then
          for p in $(awk '{print $1}' "$remote_conf"); do
            test_entry "$p" || true
          done
        fi
      else
        test_entry "$1"
      fi
      ;;

    chrome)
      open -a "Google Chrome" --args --proxy-pac-url="http://localhost:$pac_port/susops.pac"
      ;;

    chrome-proxy-settings)
      open -a "Google Chrome" "chrome://net-internals/#proxy"
      ;;

    firefox)
      local PROFILE="$workspace/firefox_profile"
      mkdir -p "$PROFILE"
      printf 'user_pref("network.proxy.type", 2);\nuser_pref("network.proxy.autoconfig_url", "http://localhost:%s/susops.pac");' "$pac_port" > "$PROFILE/user.js"
      open -a "Firefox" --args -profile "$PROFILE" -no-remote
      ;;

    *)
      susops help
      return 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  susops "$@"
fi