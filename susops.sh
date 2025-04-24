#!/usr/bin/env bash

susops() {
  # Disable job control PID output
  set +m

  # Defaults
  local ssh_host="${SUSOPS_SSH_HOST:-pi}"
  local workspace="${SUSOPS_WORKSPACE:-$HOME/.susops}"

  # Define file paths for storing ports, PIDs, and config
  local socks_portfile="$workspace/socks_port"
  local pac_portfile="$workspace/pac_port"
  local pacfile="$workspace/susops.pac"
  local socks_pidfile="$workspace/socks.pid"
  local pac_pidfile="$workspace/pac.pid"
  local remote_conf="$workspace/remote.conf"
  local local_conf="$workspace/local.conf"

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
  local socks_port=$(load_port "$socks_portfile")
  local pac_port=$(load_port "$pac_portfile")

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
    local pidfile=$1 description=$2 print=false port=$4 additional=$5
    [[ $pidfile ]] || return 1
    [[ $description ]] || description="Service"
    [[ $3 == true ]] && print=true

    if [[ -f "$pidfile" ]]; then
      local pid; pid=$(<"$pidfile")
      if kill -0 "$pid" 2>/dev/null; then
        local pid_string="PID $pid"
        if [[ $port ]]; then
          local nc_pid=$(pgrep -f "nc -l $port")
          if [[ $nc_pid ]]; then
            pid_string="PIDs $pid & $nc_pid"
          fi
        fi
        if [[ $additional ]]; then
          $print && align_printf "✅ running (%s, port %s, %s)" "$description:" "$pid_string" "$port" "$additional"
        else
          $print && align_printf "✅ running (%s, port %s)" "$description:" "$pid_string" "$port"
        fi
        return 0
      fi
    fi
    $print && align_printf "⚠️ not running" "$description:"
    return 1
  }

  test_entry() {
    local target=$1
    if [[ ! $target =~ ^[0-9]+$ ]]; then
      if curl -s --max-time 5 --proxy socks5h://127.0.0.1:"$socks_port" "https://$target" >/dev/null 2>&1; then
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

  case $cmd in
    help|-h)
      cat << EOF
Usage: susops [-v|--verbose] COMMAND [ARGS]
Commands:
  add [-l REMOTE_PORT LOCAL_PORT] [-r LOCAL_PORT REMOTE_PORT] [HOST]  add hostname or port forward, schema FROM -> TO
  rm  [-l LOCAL_PORT]             [-r REMOTE_PORT]            [HOST]  remove hostname or port forward
  restart                                                             stop and start (preserves ports)
  start [ssh_host] [socks_port] [pac_port]                            start proxy and PAC server
  stop                                                                stop proxy and server
  ls                                                                  list PAC hosts and remote forwards
  ps                                                                  show status, ports, and remote forwards
  reset                                                               remove all files and configs
  test (--all|TARGET)                                                 test connectivity
  chrome                                                              launch Chrome with proxy
  chrome-proxy-settings                                               open Chrome proxy settings
  firefox                                                             launch Firefox with proxy
Options:
  -v, --verbose                                                       enable verbose output
EOF
      ;;

    add)
      case "$1" in
        -l)
          local rport=$2 lport=$3
          [[ $rport && $lport ]] || { echo "Usage: susops add -l REMOTE_PORT LOCAL_PORT"; echo "Map a port from a remote server to your localhost"; return 1; }

          # 1) Exact rule must not already exist locally
          if grep -q "^${lport} ${rport}\$" "$local_conf" 2>/dev/null; then
            echo "Local forward $ssh_host:${rport} -> localhost:${lport} already registered"
            return 1

          # 2) LOCAL_PORT must not already be used
          elif grep -q "^${lport} " "$local_conf" 2>/dev/null; then
            echo "Local port ${lport} is already the source of a local forward"
            return 1

          # 3) LOCAL_PORT must not be targeted by any remote forward
          elif grep -q "^[0-9]\+ ${lport}\$" "$remote_conf" 2>/dev/null; then
            echo "Local port ${lport} is already the target of a remote forward"
            return 1

          # 4) REMOTE_PORT must not be the source of any remote forward
          elif grep -q "^${rport} " "$remote_conf" 2>/dev/null; then
            echo "Remote port ${rport} is already the source of a remote forward"
            return 1

          else
            echo "${lport} ${rport}" >> "$local_conf"
            echo "Registered local forward $ssh_host:${rport} -> localhost:${lport}"
            is_running "$socks_pidfile" && echo "Run \"susops restart\" to apply"
          fi
          ;;

        -r)
          local lport=$2 rport=$3
          [[ $lport && $rport ]] || { echo "Usage: susops add -r LOCAL_PORT REMOTE_PORT"; echo "Map a port from your localhost to a remote server"; return 1; }

          # 1) Exact rule must not already exist remotely
          if grep -q "^${rport} ${lport}\$" "$remote_conf" 2>/dev/null; then
            echo "Remote forward localhost:${lport} -> $ssh_host:${rport} already registered"
            return 1

          # 2) REMOTE_PORT must not already be used
          elif grep -q "^${rport} " "$remote_conf" 2>/dev/null; then
            echo "Remote port ${rport} is already registered"
            return 1

          # 3) REMOTE_PORT must not be targeted by any local forward
          elif grep -q "^[0-9]\+ ${rport}\$" "$local_conf" 2>/dev/null; then
            echo "Remote port ${rport} is already the target of a local forward"
            return 1

          # 4) LOCAL_PORT must not be the source of a local forward
          elif grep -q "^${lport} " "$local_conf" 2>/dev/null; then
            echo "Local port ${lport} is already the source of a local forward"
            return 1

          else
            echo "${rport} ${lport}" >> "$remote_conf"
            echo "Registered remote forward localhost:${lport} -> $ssh_host:${rport}"
            is_running "$socks_pidfile" && echo "Run \"susops restart\" to apply"
          fi
          ;;

        *)
          local host=$1
          [[ $host ]] || { echo "Usage: add [HOST] [-l REMOTE_PORT LOCAL_PORT] [-r LOCAL_PORT REMOTE_PORT] "; echo "Ports are mapped in schema FROM -> TO"; return 1; }
          if grep -q "host === \"$host\"" "$pacfile"; then
            echo "$host already in PAC"
          else
            awk -v h="$host" '/return "DIRECT"/ { print "  if (host === \""h"\" || dnsDomainIs(host, \"."h"\")) return \"SOCKS5 127.0.0.1:'$socks_port'\";" }1' \
              "$pacfile" > "$workspace/tmp.pac" && mv "$workspace/tmp.pac" "$pacfile"
            echo "Added $host to PAC"
            is_running "$socks_pidfile" "SOCKS5 proxy" && test_entry "$host"
            return 0
          fi
          ;;
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
            is_running "$socks_pidfile" && echo "Run \"susops restart\" to apply"
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
            is_running "$socks_pidfile" && echo "Run \"susops restart\" to apply"
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
            echo "Removed $host"
          else
            echo "$host not found in PAC file."
            if [[ $host =~ ^[0-9]+$ ]]; then echo "Use \"susops -l LOCAL_PORT\" OR \"susops -r REMOTE_PORT\" to remove a forwarded port"; fi
            return 1
          fi
          ;;
      esac
      ;;

    restart)
      susops stop true
      susops start
      ;;

    start)
      local target=${1:-$ssh_host}
      [[ $2 ]] && socks_port=$2 && echo "$socks_port" > "$socks_portfile"
      [[ $3 ]] && pac_port=$3 && echo "$pac_port" > "$pac_portfile"
      sed -E -i '' "s#(SOCKS5 127\\.0\\.0\\.1:)[0-9]+#\\1$socks_port#g" "$pacfile"

      # Only start SOCKS proxy if not already running
      if [[ -f "$socks_pidfile" ]] && kill -0 "$(<"$socks_pidfile")" 2>/dev/null; then
        is_running "$socks_pidfile" "SOCKS5 proxy" true "$socks_port"
      else
        # Build remote tunnel arguments
        local remote_args=()
        [[ -f "$remote_conf" ]] && while read -r rp lp; do remote_args+=("-R" "${rp}:localhost:${lp}"); done < "$remote_conf"
        # Build local forward arguments
        local local_args=()
        [[ -f "$local_conf" ]] && while read -r lp rp; do local_args+=("-L" "${lp}:localhost:${rp}"); done < "$local_conf"

        # Build SSH command
        local ssh_cmd=( autossh -M 0 -N -T -D "$socks_port" "${remote_args[@]}" "${local_args[@]}" "$target" )
        if ! command -v autossh >/dev/null 2>&1; then
          $verbose && echo "autossh not found, falling back to ssh."
          ssh_cmd=( "$ssh_command" -N -T -D "$socks_port" "${remote_args[@]}" "${local_args[@]}" "$target" )
        fi

        $verbose && printf "Full SSH command: %s\n" "${ssh_cmd[*]}"
        nohup "${ssh_cmd[@]}" </dev/null >/dev/null 2>&1 &
        echo $! > "$socks_pidfile"

        align_printf "🚀 started (PID %s, port %s)" "SOCKS5 proxy:" "$(<"$socks_pidfile")" "$socks_port"
      fi

      # Only start PAC server if not already running
      if [[ -f "$pac_pidfile" ]] && kill -0 "$(<"$pac_pidfile")" 2>/dev/null; then
        is_running "$pac_pidfile" "PAC server" true "$pac_port" "URL: http://localhost:$pac_port/susops.pac"
      else
        length=$(wc -c <"$pacfile")
        nohup bash -c "
          while true; do
            {
              printf 'HTTP/1.1 200 OK\r\n'
              printf 'Content-Type: application/x-ns-proxy-autoconfig\r\n'
              printf 'Content-Length: %s\r\n' \"$length\"
              printf 'Connection: close\r\n'
              printf '\r\n'
              cat \"$pacfile\"
            } | nc -l \"$pac_port\"
          done
        " </dev/null >/dev/null 2>&1 &
        echo $! > "$pac_pidfile"

        local max_wait=5
        local interval=0.1
        steps=$(printf "%.0f" "$(echo "$max_wait / $interval" | bc -l)")  # workaround, $i has to be an integer value
        for ((i=0; i<steps; i++)); do
          if nc_pid=$(pgrep -f "nc -l $pac_port"); then
            align_printf "🚀 started (PIDs %s & %s, port %s, URL %s)" "PAC server:" "$(<"$pac_pidfile")" "$nc_pid" "$pac_port" "http://localhost:$pac_port/susops.pac"
            break
          fi
          $verbose && printf "Waiting for PAC server to start... (%d/%d)\n" "$i+1" "$steps"
          sleep "$interval"
        done
        if [[ $i -ge $steps ]]; then
          align_printf "⚠️ partially started (PID %s, port %s, URL %s)" "PAC server:" "$(<"$pac_pidfile")" "$pac_port" "http://localhost:$pac_port/susops.pac"
          return 1
        fi
      fi
      ;;

    stop)
      local restarting=false
      [[ $1 == true ]] && restarting=true
      if [[ -f "$socks_pidfile" ]] && kill -0 "$(<"$socks_pidfile")" 2>/dev/null; then
        kill "$( <"$socks_pidfile")" 2>/dev/null
        rm -f "$socks_pidfile" "$socks_portfile"
        align_printf "🛑 stopped" "SOCKS5 proxy:"
      else
        [[ $restarting == false ]] && align_printf "⚠️ not running" "SOCKS5 proxy:"
      fi
      if [[ -f "$pac_pidfile" ]] && kill -0 "$(<"$pac_pidfile")" 2>/dev/null; then
        local pid=$(<"$pac_pidfile")
        kill "$pid" 2>/dev/null
        pkill -f "nc -l $pac_port" 2>/dev/null
        rm -f "$pac_pidfile" "$pac_portfile"
        align_printf "🛑 stopped" "PAC server:"
      else
        [[ $restarting == false ]] && align_printf "⚠️ not running" "PAC server:"
      fi
      ;;

    ls)
      echo "PAC hosts:"
      sed -n 's/.*host === "\([^"]*\)".*/→ \1/p' "$pacfile" || echo "→ None"
      echo "Local forwards:"
      if [[ -s "$local_conf" ]]; then
        while read -r lp rp; do echo "→ $ssh_host:$rp -> localhost:$lp"; done < "$local_conf"
      else
        echo "→ None"
      fi
      echo "Remote forwards:"
      if [[ -s "$remote_conf" ]]; then
        while read -r rp lp; do echo "→ localhost:$lp -> $ssh_host:$rp"; done < "$remote_conf"
      else
        echo "→ None"
      fi
      ;;

    ps)
      is_running "$socks_pidfile" "SOCKS5 proxy" true "$socks_port"
      is_running "$pac_pidfile" "PAC server" true "$pac_port" "URL: http://localhost:$pac_port/susops.pac"
      ;;

    reset)
      echo "This will stop susops and remove all of its configs"
      printf "Are you sure? [y/N] "
      read -r user_decision
      if [[ ! $user_decision =~ ^[Yy]$ ]]; then
        return 1
      fi

      susops stop true
      rm -rf "$workspace"
      echo "Removed all files and configs"
      ;;

    test)
      [[ $1 ]] || { echo "Usage: susops test (--all|TARGET)"; return 1; }
      is_running "$socks_pidfile" "SOCKS5 proxy" || { align_printf "⚠️ not running, use \"susops start\" first" "SOCKS5 proxy:"; return 1; }
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