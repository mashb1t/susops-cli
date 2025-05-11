#!/usr/bin/env bash

susops() {
  # Disable job control PID output
  set +m

  # Defaults
  local -r workspace="${SUSOPS_WORKSPACE:-$HOME/.susops}"
#  local -r workspace="."

  # Define file paths for storing ports and config
  local -r pacfile="$workspace/susops.pac"
  local -r cfgfile="$workspace/config.yaml"

  # Define process names for easier identification
  local -r SUSOPS_SSH_PROCESS_NAME="susops-ssh"
  local -r SUSOPS_PAC_LOOP_PROCESS_NAME="susops-pac-loop"
  local -r SUSOPS_PAC_NC_PROCESS_NAME="susops-pac-nc"
  local -r SUSOPS_PAC_UNIFIED_PROCESS_NAME="susops-pac"

  mkdir -p "$workspace"

    # Bootstrap config if missing
  if [[ ! -f "$cfgfile" ]]; then
    cat >"$cfgfile" <<EOF
pac_server_port: 0
connections: []
EOF
  fi

  # Parse global flags: --conn TAG, --verbose
  local verbose=false conn_tag="" conn_specified=false
  local args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v|--v|--verbose) verbose=true; shift ;;
      -c|--c|--connection) conn_tag=$2; conn_specified=true; shift 2 ;;
      *) args+=("$1"); shift ;;
    esac
  done
  set -- "${args[@]}"

  # Ensure at least one sub-command is provided
  [[ $1 ]] || { susops help; return 1; }
  local cmd=$1; shift

  # Default to first connection if none specified
  if [[ -z $conn_tag ]]; then
    conn_tag=$(yq e '.connections[0].tag' "$cfgfile")
    if [[ $conn_tag == "null" && $cmd != "add-connection" ]]; then
      echo "No connection specified and no default connection found."
      echo "Please add a connection using:
susops add-connection <tag> <ssh_host> [<socks_proxy_port>]
      "
      cmd="invalid-command" # shows help and returns 1
    fi
  fi
  $verbose && echo "Connection tag: $conn_tag"

  # Helper: run susops.sh with consistent arguments (connection and verbose tags)
  run_susops() {
    local args=("$@")
    if [[ $verbose == true ]]; then
      args=("-v" "${args[@]}")
    fi
    susops -c "$conn_tag" "${args[@]}"
#    ./susops.sh -c "$conn_tag" "${args[@]}"
  }

  get_connection_tags() {
    if $conn_specified; then
      # If a specific connection is specified, return only that tag
      yq e ".connections[] | select(.tag==\"$conn_tag\").tag" "$cfgfile"
    else
      # Otherwise, return all connection tags
      yq e '.connections[].tag' "$cfgfile"
    fi
  }

  # Helper: run yq in-place
  update_cfg() {
    yq e -i "$1" "$cfgfile";
  }

  # Load or generate a port: global pac_server_port or per-connection socks_proxy_port
  load_port() {
    local key=$1 filter
    local conn_tag=${2:-$conn_tag}
    if [[ $key == pac_server_port ]]; then
      filter=".pac_server_port"
    else
      filter=".connections[] | select(.tag==\"$conn_tag\").$key"
    fi
    local cur=$(yq e "$filter" "$cfgfile" | head -1)
    if [[ $cur =~ ^[0-9]+$ ]] && [[ $cur -gt 0 ]]; then
      echo $cur
    else
      local raw port
      raw=$(head -c2 /dev/random | od -An -tu2 | tr -d ' ')
      port=$(( raw % 16384 + 49152 ))
      if [[ $key == pac_server_port ]]; then
        update_cfg ".pac_server_port = $port"
      else
        update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") .${key} = $port)"
      fi
      echo $port
    fi
  }

  # Fetch global and per-connection ports and host
  pac_port=$(load_port pac_server_port)
  socks_port=$(load_port socks_proxy_port)
  ssh_host=$(yq e ".connections[] | select(.tag==\"$conn_tag\").ssh_host" "$cfgfile")

  # (Re)generate unified PAC file with rules for all connections
  write_pac_file() {
    {
      echo 'function FindProxyForURL(url, host) {'
      for tag in $(yq e '.connections[].tag' "$cfgfile"); do
        local socks_proxy_port
        socks_proxy_port=$(yq e ".connections[] | select(.tag==\"$tag\").socks_proxy_port" "$cfgfile")
        yq e ".connections[] | select(.tag==\"$tag\") | .pac_hosts[]" "$cfgfile" | while read -r host; do
          echo "  if (host == '$host' || dnsDomainIs(host, '.$host')) return 'SOCKS5 127.0.0.1:$socks_proxy_port';"
        done
      done
      echo '  return "DIRECT";'
      echo '}'
    } > "$pacfile"
  }

  # Helper to build port-forward args for both local and remote
  build_args() {
    local key=$1 flag=$2 conn_tag=${3:-$conn_tag}
    args=()
    while IFS=' ' read -r src dst; do
      [[ -z $src || -z $dst ]] && continue
      args+=("$flag" "${src}:localhost:${dst}")
    done < <(
      yq eval "
        .connections[]
        | select(.tag == \"$conn_tag\")
        | (.forwards.$key // [])[]
        | select(.src and .dst)
        | \"\(.src) \(.dst)\"
      " $cfgfile
    )
    echo "${args[@]}"
  }

  align_printf() {
    local format=$1; shift
    local args=("$@")
    printf "%-25s $format\n" "${args[@]}"
  }

  ##############################################################################
  # is_running  <proc-pattern>  [description] [print?] [port] [extra] [exact?]
  # ----------------------------------------------------------------------------
  # • proc-pattern  – String passed to pgrep -f.
  #                  If exact? is “true” (6th arg) we anchor it with ^…$ so
  #                             only a *full-command* match is returned.
  # • description   – Label printed in the first column (defaults to “Service”).
  # • print?        – “true”  → always print a status line (✅/⚠️).
  #                  – “false” → stay silent; caller checks exit status only.
  # • port / extra  – Optional bits appended to the status line.
  # • exact?        – “true” or “false” (default); see above.
  #
  # Return value    – 0 if *any* matching PIDs found, 1 otherwise.
  ##############################################################################
  is_running() {
    local pattern=$1
    local exact=${2:-true}
    local do_print=${3:-false}
    local desc=${4:-Service}
    local port=$5
    local extra=$6

    local pids

    if [[ $exact == true ]]; then
      pids=$(pgrep -x "${pattern}" 2>/dev/null || :)
    else
      pids=$(pgrep -f "${pattern}"   2>/dev/null || :)
    fi

    if [[ -n $pids ]]; then
      # Build “PID 123 456” or “PIDs 123 456”
      local list
      list=$(printf '%s\n' "$pids" | awk '{print $1}' | xargs)
      local how_many
      how_many=$(wc -w <<< "$list")
      local label="PID"
      [[ $how_many -gt 1 ]] && label="PIDs"
      [[ $do_print == true ]] && {
        if [[ -n $extra ]]; then
          align_printf "✅ running (%s %s%s%s)" "$desc:" "$label" "$list" "${port:+, port $port}" ", $extra"
        else
          align_printf "✅ running (%s %s%s)" "$desc:" "$label" "$list" "${port:+, port $port}"
        fi
      }
      return 0
    fi

    # --- Not running ---------------------------------------------------------
    [[ $do_print == true ]] && align_printf "⚠️ not running" "$desc:"
    return 1
  }

  ##############################################################################
  # stop_by_name  <proc-pattern>  [label] [exact?]
  # ----------------------------------------------------------------------------
  # • proc-pattern – String passed to pgrep -f
  #                  If exact? (3rd arg) is “true”, anchors with ^…$ so only an
  #                  exact full-command match returns (same convention as
  #                  is_running).
  # • label        – Human-readable label, e.g. "SOCKS5 proxy"  (optional)
  # • exact?       – "true" | "false" (default false)
  #
  # Behaviour
  #   – Finds every matching PID, kills them (SIGTERM).
  #   – Prints 🛑 stopped / ⚠️ not running lines in the same aligned style
  #     as is_running / align_printf.
  #   – No port-file cleanup here (ports now live in config.yaml and are
  #     cleared by the caller, e.g. in `susops stop`).
  ##############################################################################
  stop_by_name() {
    local pattern=$1
    local label=$2
    local keep_ports=${3:-false}
    local tag=${4:-false}
    local exact=${5:-false}

    local pids

    if [[ $exact == true ]]; then
      pids=$(pgrep -x "$pattern" 2>/dev/null || :)
    else
      pids=$(pgrep -f "$pattern" 2>/dev/null || :)
    fi

    if [[ -n $pids ]]; then
      # Terminate every PID that is still alive
      for pid in $(printf '%s\n' "$pids" | awk '{print $1}'); do
        kill "$pid" 2>/dev/null
      done

      # zero out the socks_proxy_port unless user asked to keep
      if [[ $keep_ports == false && -n "$tag" ]]; then
        yq e -i "(.connections[] | select(.tag==\"$tag\")).socks_proxy_port = 0" "$cfgfile"
      fi

      align_printf "🛑 stopped" "${label:-Service}:"
      return 0
    fi

    align_printf "⚠️ not running" "${label:-Service}:"
    return 1
  }

  # Helper: single host/port test
  ############################################################
  test_entry() {
    local target=$1
    local conn_tag=${2:-$conn_tag}
    if [[ $target =~ ^[0-9]+$ ]]; then
      # Target looks like a port → could be local or remote
      if yq e ".connections[] | select(.tag==\"$conn_tag\").forwards.local[]?
               | select(.src == $target)" "$cfgfile" | grep -q . >/dev/null; then
        # Local forward exists: test localhost:src
        $verbose && echo "Testing local forward $target on localhost"
        if curl -s --max-time 5 "http://localhost:$target" >/dev/null 2>&1; then
          printf "✅ local:%s (localhost:%s → %s:%s)\n" \
                 "$target" "$target" "$ssh_host" \
                 "$(yq e '.forwards.local[] | select(.src=='"$target"').dst' \
                         <<<"$(yq e '.connections[] | select(.tag=="'"$conn_tag"'")' "$cfgfile")")"
          return 0
        else
          printf "❌ local:%s unreachable\n" "$target"
          return 1
        fi
      elif yq e ".connections[] | select(.tag==\"$conn_tag\").forwards.remote[]?
                 | select(.src == $target)" "$cfgfile" | grep -q . >/dev/null; then
        # Remote forward exists: test via ssh on remote side
        $verbose && echo "Testing remote forward $target on $ssh_host"
        if ssh "$ssh_host" curl -s --max-time 5 "http://localhost:$target" >/dev/null 2>&1; then
          printf "✅ remote:%s (%s:%s → localhost:%s)\n" \
                 "$target" "$ssh_host" "$target" \
                 "$(yq e '.forwards.remote[] | select(.src=='"$target"').dst' \
                         <<<"$(yq e '.connections[] | select(.tag=="'"$conn_tag"'")' "$cfgfile")")"
          return 0
        else
          printf "❌ remote:%s unreachable\n" "$target"
          return 1
        fi
      else
        printf "❌ Port %s not found in forwards\n" "$target"
        return 1
      fi
    else
      # Host test through SOCKS proxy
      if curl -s -k --max-time 5 \
             --proxy "socks5h://127.0.0.1:$socks_port" \
             "https://$target" >/dev/null 2>&1; then
        printf "✅ %s via SOCKS\n" "$target"; return 0
      else
        printf "❌ %s via SOCKS\n" "$target"; return 1
      fi
    fi
  }

  validate_port_in_range() {
    # $1: port
    [[ $1 =~ ^[0-9]+$ && $1 -ge 1 && $1 -le 65535 ]]
  }

  check_exact_rule() {
    # $1: src, $2: dst, $3: type (local|remote)
    yq e ".connections[].forwards.$3[] | select(.src==\"$1\" and .dst==\"$2\")" "$cfgfile" | grep -q . && return 0
    return 1
  }

  check_port_source() {
    # $1: port, $2: type (local|remote)
    yq e ".connections[].forwards.$2[] | select(.src==\"$1\")" "$cfgfile" | grep -q . && return 0
    return 1
  }

  check_port_target() {
    # $1: port, $2: type (local|remote)
    yq e ".connections[].forwards.$2[] | select(.dst==\"$1\")" "$cfgfile" | grep -q . && return 0
    return 1
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
Usage: susops [-v|--verbose] [-c|--connection TAG] COMMAND [ARGS]
Commands:
  add-connection TAG SSH_HOST [SOCKS_PORT]                                        add a new connection
  rm-connection  TAG                                                              remove a connection
  add [-l LOCAL_PORT REMOTE_PORT [TAG]] [-r REMOTE_PORT LOCAL_PORT [TAG]] [HOST]  add hostname or port forward, schema source → target
  rm  [-l LOCAL_PORT|TAG]               [-r REMOTE_PORT|TAG]              [HOST]  remove hostname or port forward
  start   [SSH_HOST] [SOCKS_PORT] [PAC_PORT]                                      start proxy and PAC server
  stop    [--keep-ports]                                                          stop proxy and server (if no other proxies are running)
  restart                                                                         stop and start (preserves ports)
  ps                                                                              show status, ports, and forwards
  ls                                                                              output current config
  config                                                                          open config file in an editor
  reset   [--force]                                                               remove all files and configs
  test    --all|TARGET                                                            test connectivity
  chrome                                                                          launch Chrome with proxy
  chrome-proxy-settings                                                           open Chrome proxy settings
  firefox                                                                         launch Firefox with proxy
  help, --help, -h                                                                show this help message
Options:
  -v, --verbose                                                                   enable verbose output
  -c, --connection TAG                                                            specify connection tag
EOF
      ;;

    ##############################################################################
    # add_connection <tag> [ssh_host] [socks_proxy_port]
    # - Creates a new empty connection block.
    # - Fails if the tag already exists or is empty/contains spaces.
    ##############################################################################
    add-connection)
      local tag=$1
      local ssh_host=${2:-""}
      local socks_proxy_port=$3

      [[ -z $tag || $tag =~ [[:space:]] ]] && { echo "Usage: susops add-connection TAG"; echo "TAG must not contain a whitespace"; return 1; }

      # Abort if tag already present
      if yq e ".connections[] | select(.tag == \"$tag\")" "$cfgfile" | grep -q . >/dev/null; then
        echo "Error: connection '$tag' already exists"
        return 1
      fi

      [[ -z $ssh_host ]] && { echo "Error: SSH host is required"; return 1; }

      if [[ -z $socks_proxy_port ]]; then
        socks_proxy_port=$(load_port socks_proxy_port "$tag")
      elif ! validate_port_in_range "$socks_proxy_port"; then
        echo "Error: socks_proxy_port must be a valid port in range 1 to 65535"
        return 1
      elif yq e ".connections[] | select(.socks_proxy_port == $socks_proxy_port)" "$cfgfile" | grep -q . >/dev/null; then
        echo "Error: socks_proxy_port $socks_proxy_port is already in use by another connection"
        return 1
      fi

      # Test ssh connection to host
      if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$ssh_host" exit 2>/dev/null; then
        echo "Error: SSH connection to host '$ssh_host' failed"
        return 1
      fi

      # Append new entry
      yq e -i \
        ".connections += [{\"tag\": \"$tag\", \"ssh_host\": \"$ssh_host\", \
                           \"socks_proxy_port\": $socks_proxy_port, \
                           \"forwards\": {\"local\": [], \"remote\": []}, \
                           \"pac_hosts\": []}]" \
        "$cfgfile"

      align_printf "✅ tested & added" "Connection [$tag]:"
      ;;

    ##############################################################################
    # remove_connection <tag>
    # - Stops the connection if running, then deletes its YAML block.
    ##############################################################################
    rm-connection)
      local tag=$1
      [[ -z $tag ]] && { echo "Usage: susops rm-connection TAG"; return 1; }

      if ! yq e ".connections[] | select(.tag == \"$tag\")" "$cfgfile" | grep -q . >/dev/null; then
        align_printf "❌ not found" "Connection [$tag]:"
        return 1
      fi

       # Stop tunnel if still running
      stop_by_name "susops-ssh-$tag" "SOCKS5 proxy [$tag]" false "$tag" >/dev/null

      # check if connection has hosts
      local has_hosts
      has_hosts=$(yq e ".connections[] | select(.tag == \"$tag\") | .pac_hosts" "$cfgfile" | grep -q . >/dev/null)
      # delete connection
      yq e -i "del(.connections[] | select(.tag == \"$tag\"))" "$cfgfile"

      local hint=""
      if [[ $has_hosts ]]; then
        hint=". Please reload your browser proxy settings."
      fi

      align_printf "✅ stopped & removed $hint" "Connection [$tag]:"
      return 0
      ;;

    add)
      case "$1" in
        -l)
          local lport=$2 rport=$3 tag=${4:-""}
          [[ $lport && $rport ]] || {
            echo "Usage: susops add -l LOCAL_PORT REMOTE_PORT [TAG]"
            echo "Map a port from a remote server to your localhost"
            return 1
          }

          [[ -z $tag || $tag =~ [[:space:]] ]] && tag="$lport"

          if ! validate_port_in_range "$lport"; then
            echo "LOCAL_PORT must be a valid port in range 1 to 65535"
            return 1
          elif ! validate_port_in_range "$rport"; then
            echo "REMOTE_PORT must be a valid port in range 1 to 65535"
            return 1
          elif check_exact_rule "$lport" "$rport" "local"; then
            echo "Local forward localhost:${lport} → $ssh_host:${rport} is already registered"
            return 1
          elif check_port_source "$lport" "local"; then
            echo "Local port ${lport} is already the source of a local forward"
            return 1
          elif check_port_target "$lport" "local"; then
            echo "Local port ${lport} is already the target of a remote forward"
            return 1
          elif check_port_source "$rport" "remote"; then
            echo "Remote port ${rport} is already the source of a remote forward"
            return 1
          elif check_port_in_use "$lport"; then
            echo "Local port $lport is already in use on localhost"
            return 1
          else
            update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") .forwards.local += [{\"tag\": \"$tag\", \"src\": $lport, \"dst\": $rport}])"
            align_printf "✅ Added local forward [${tag}] localhost:${lport} → ${ssh_host}:${rport}" "Connection [$conn_tag]:"
            is_running "$SUSOPS_SSH_PROCESS_NAME-$conn_tag" && echo "Restart proxy to apply"
            return 0
          fi
          ;;

        -r)
          local rport=$2 lport=$3
          [[ $rport && $lport ]] || {
            echo "Usage: susops add -r REMOTE_PORT LOCAL_PORT [TAG]"
            echo "Map a port from your localhost to a remote server"
            return 1
          }

          if ! validate_port_in_range "$rport"; then
            echo "REMOTE_PORT must be a valid port in range 1 to 65535"
            return 1
          elif ! validate_port_in_range "$lport"; then
            echo "LOCAL_PORT must be a valid port in range 1 to 65535"
            return 1
          elif check_exact_rule "$rport" "$lport" "remote"; then
            echo "Remote forward $ssh_host:${rport} → localhost:${lport} is already registered"
            return 1
          elif check_port_source "$rport" "remote"; then
            echo "Remote port ${rport} is already the source of a remote forward"
            return 1
          elif check_port_target "$rport" "remote"; then
            echo "Remote port ${rport} is already the target of a local forward"
            return 1
          elif check_port_source "$lport" "local"; then
            echo "Local port ${lport} is already the source of a local forward"
            return 1
          elif check_port_in_use "$rport" "$ssh_host"; then
            echo "Remote port $rport is already in use on $ssh_host"
            return 1
          else
            update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") .forwards.remote += [{\"tag\": \"$tag\", \"src\": $rport, \"dst\": $lport}])"
            align_printf "✅ Added remote forward [${tag}] ${ssh_host}:${rport} → localhost:${lport}" "Connection [$conn_tag]:"
            is_running "$SUSOPS_SSH_PROCESS_NAME-$conn_tag" && echo "Restart proxy to apply"
            return 0
          fi
          ;;

        *)
          local host=$1
          [[ $host ]] || {
            echo "Usage: susops add [HOST]";
            return 1;
          }

          if yq e ".connections[].pac_hosts[] | select(.==\"$host\")" "$cfgfile" | grep -q .; then
            echo "Error: PAC host '$host' already exists in a connection"
            return 1
          fi

          host=$(echo "$host" | sed -E 's/^[^:]+:\/\///; s/\/.*//')

          update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") .pac_hosts += [\"$host\"])"
          write_pac_file

          align_printf "✅ Added $host" "Connection [$conn_tag]:"
          is_running "$SUSOPS_SSH_PROCESS_NAME-$conn_tag" && (test_entry "$host"; echo "Please reload your browser proxy settings.")
          return 0
      esac
      ;;

    rm)
      case "$1" in
        -l)
          local lport=$2
          [[ $lport ]] || { echo "Usage: susops rm -l LOCAL_PORT"; return 1; }
          if check_port_source "$lport" "local"; then
            update_cfg "del(.connections[].forwards.local[] | select(.tag==$lport or .src==$lport))"
            echo "Removed local forward localhost:$lport"
            is_running "$SUSOPS_SSH_PROCESS_NAME-$conn_tag" && echo "Restart proxy to apply"
            return 0
          else
            echo "No local forward for localhost:$lport"
            return 1
          fi
          ;;

        -r)
          local rport=$2
          [[ $rport ]] || { echo "Usage: susops rm -r REMOTE_PORT"; return 1; }
          if check_port_source "$rport" "remote"; then
            update_cfg "del(.connections[].forwards.remote[] | select(.tag==$rport or .src==$rport))"
            echo "Removed remote forward $ssh_host:$rport"
            is_running "$SUSOPS_SSH_PROCESS_NAME-$conn_tag" && echo "Restart proxy to apply"
            return 0
          else
            echo "No remote forward for $ssh_host:$rport"
            return 1
          fi
          ;;

        *)
          local host=$1
          [[ $host ]] || { echo "Usage: rm [HOST] [-l LOCAL_PORT] [-r REMOTE_PORT]"; return 1; }

          if yq e ".connections[].pac_hosts[] | select(.==\"$host\")" "$cfgfile" | grep -q .; then
            update_cfg "del(.connections[].pac_hosts[] | select(.==\"$host\"))"
            write_pac_file
            echo "Removed $host from all connections"
            is_running "$SUSOPS_SSH_PROCESS_NAME-$conn_tag" && echo "Please reload your browser proxy settings."
            return 0
          else
            echo "$host not found in any connection"
            if [[ $host =~ ^[0-9]+$ ]]; then echo "Use \"susops -l LOCAL_PORT\" OR \"susops -r REMOTE_PORT\" to remove a forwarded port"; fi
            return 1
          fi
          ;;
      esac
      ;;

    restart)
      run_susops stop --keep-ports
      run_susops start
      ;;

    start)
      [[ -n $1 ]] && ssh_host=$1 && update_cfg   "(.connections[] | select(.tag==\"$conn_tag\")).ssh_host = \"$ssh_host\""
      [[ -n $2 ]] && socks_port=$2 && update_cfg "(.connections[] | select(.tag==\"$conn_tag\")).socks_proxy_port = $socks_port"
      [[ -n $1 ]] || [[ -n $2 ]] && stop_by_name "$SUSOPS_SSH_PROCESS_NAME-$conn_tag" "SOCKS5 proxy [$conn_tag]" true

      [[ -n $3 ]] && pac_port=$3 && update_cfg   ".pac_server_port = $pac_port" && stop_by_name "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" "PAC server" true

      for tag in $(get_connection_tags); do
        ssh_host=$(yq e ".connections[] | select(.tag==\"$tag\").ssh_host" "$cfgfile")
        socks_port=$(load_port socks_proxy_port "$tag")

        # Start SOCKS proxy for chosen connection
        if is_running "$SUSOPS_SSH_PROCESS_NAME-$tag" >/dev/null; then
          is_running "$SUSOPS_SSH_PROCESS_NAME-$tag" true true "SOCKS5 [$tag]" "$socks_port" "SSH host: $ssh_host"
        else
          local_args=$(build_args "local" "-L" "$tag")
          remote_args=$(build_args "remote" "-R" "$tag")
          local ssh_cmd=(autossh -M 0 -N -T -D "$socks_port" "${local_args[@]}" "${remote_args[@]}" "$ssh_host")
          if ! command -v autossh >/dev/null 2>&1; then
            $verbose && echo "autossh not found, falling back to ssh"
            ssh_cmd=( ssh -N -T -D "$socks_port" "${local_args[@]}" "${remote_args[@]}" "$ssh_host" )
          fi

          $verbose && printf "Full SSH command: %s\n" "nohup bash -c 'exec -a $SUSOPS_SSH_PROCESS_NAME ${ssh_cmd[*]}' </dev/null >/dev/null 2>&1 &"
          nohup bash -c "exec -a $SUSOPS_SSH_PROCESS_NAME-$tag ${ssh_cmd[*]}" </dev/null >/dev/null 2>&1 &
          align_printf "🚀 started (PID %s, port %s, SSH host: %s)" "SOCKS5 [$tag]:" "$!" "$socks_port" "$ssh_host"
        fi
      done

      # persist changes for ephemeral ports and given arguments
      write_pac_file

      # Only start PAC server if not already running
      if is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" false >/dev/null; then
        is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" false true "PAC server" "$pac_port" "URL: http://localhost:$pac_port/susops.pac"
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
      # Usage:
      #   susops stop [--keep-ports]
      #
      # • --keep-ports keeps the ports in config.yaml unchanged; otherwise the
      #   stopped connection’s socks_proxy_port is reset to 0.

      local keep_ports=false
      [[ $1 == '--keep-ports' ]] && keep_ports=true && shift

      for tag in $(get_connection_tags); do
        stop_by_name "$SUSOPS_SSH_PROCESS_NAME-$tag" "SOCKS5 proxy [$tag]" "$keep_ports" "$tag" true
      done

      # Stop the PAC server if no other connections are running
      if ! pgrep -f $SUSOPS_SSH_PROCESS_NAME >/dev/null; then
        stop_by_name "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" "PAC server" true # keep port the same no matter if $keep_ports is set
      fi

      return 0
      ;;

    ##########################################################################
    # susops ps
    # ─────────
    # • Lists the PAC server once.
    # • Then lists every configured connection, showing:
    #     – SOCKS PID(s)   – port   – SSH host
    # • Returns 0 if *all* expected services are running, 1 otherwise.
    ##########################################################################
    ps)
      local stopped_count=0
      local overall_count=0

      ##################################################################
      # 1. Iterate over connections
      ##################################################################
      for tag in $(get_connection_tags); do
        local socks_port ssh_host
        socks_port=$(yq e ".connections[] | select(.tag==\"$tag\").socks_proxy_port" "$cfgfile")
        ssh_host=$(yq e ".connections[] | select(.tag==\"$tag\").ssh_host" "$cfgfile")

        # SOCKS / autossh status
        overall_count=$((overall_count+1))
        is_running "$SUSOPS_SSH_PROCESS_NAME-$tag" true true "SOCKS5 proxy [$tag]" "$socks_port" \
                   "SSH host: ${ssh_host:-<unset>}" || stopped_count=$((stopped_count+1))
      done

      ##################################################################
      # 2. PAC server status (single global instance)
      ##################################################################
      local pac_port
      pac_port=$(yq e '.pac_server_port' "$cfgfile")
      overall_count=$((overall_count+1))
      is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" false true "PAC server" "$pac_port" \
                 "URL: http://localhost:${pac_port}/susops.pac" || stopped_count=$((stopped_count+1))

      if [[ $stopped_count -eq 0 ]]; then
        return 0
      elif [[ $stopped_count -lt $overall_count ]]; then
        return 2
      elif [[ $stopped_count -eq $overall_count ]]; then
        return 3
      else
        return 1
      fi
      ;;

    ls)
      yq e "." "$cfgfile"
      ;;

    config)
      open "$cfgfile"
      ;;

    reset)
      # Usage: susops reset [--force]
      #
      # • Stops *all* connections and the PAC server.
      # • Removes the entire $workspace directory, including config.yaml
      #   and any cached PAC/port files.
      # • Prompts for confirmation unless --force is supplied.

      local force=false
      if [[ "$1" == "--force" ]]; then
        force=true
      fi

      if ! $force; then
        echo "This will stop every susops connection and delete all configs."
        printf "Are you sure? [y/N] "
        read -r reply
        if [[ ! $reply =~ ^[Yy]$ ]]; then
          echo "Aborted."
          return 1
        fi
      fi

      run_susops stop --keep-ports --all

      rm -rf "$workspace"
      echo "Removed workspace '$workspace' and all susops configuration."
      ;;

    ##########################################################################
    # susops test  --all | TARGET
    #
    # • TARGET can be either a hostname in pac_hosts or a numeric port
    #   (local or remote forward).  Example:  susops --conn dev test 5432
    # • --all   tests every pac_host, every local forward, and every remote
    #   forward for the *current* connection tag ($conn_tag).
    #
    # Exit status: 0 if every test passes, 1 otherwise.
    ##########################################################################
    test)
      [[ $1 ]] || { echo "Usage: susops test (--all|TARGET)"; return 1; }

      local failures=0
      local stopped=0

      for tag in $(get_connection_tags); do
        echo "----------------------------------------"
        echo "Testing connection '$tag'"
        # Pull runtime values for this connection

        local socks_port ssh_host
        socks_port=$(yq e ".connections[] | select(.tag==\"$conn_tag\").socks_proxy_port" "$cfgfile")
        ssh_host=$(yq e ".connections[] | select(.tag==\"$conn_tag\").ssh_host" "$cfgfile")

        # ---------------------------------------------------------------------
        # Ensure the SOCKS proxy for this connection is running
        # ---------------------------------------------------------------------
        if ! is_running "$SUSOPS_SSH_PROCESS_NAME-${tag}" true true "SOCKS5 proxy" "$socks_port" "SSH host: ${ssh_host:-<unset>}"; then
          stopped=$((stopped+1))
          continue
        fi

        ##################################################################
        # Run tests
        ##################################################################
        if [[ $1 == --all ]]; then
          # 1) All PAC hosts
          for host in $(yq e ".connections[]
                               | select(.tag==\"$tag\")
                               | (.pac_hosts // [])[]" "$cfgfile"); do
            test_entry "$host" "$tag" || failures=$((failures+1))
          done

          # 2) All local forwards (by src port)
          yq e ".connections[]
                | select(.tag==\"$tag\")
                | (.forwards.local // [])[].src" "$cfgfile" | while read -r port; do
            test_entry "$port" "$tag" || failures=$((failures+1))
          done

          # 3) All remote forwards (by src port on remote)
          yq e ".connections[]
                | select(.tag==\"$tag\")
                | (.forwards.remote // [])[].src" "$cfgfile" | while read -r port; do
            test_entry "$port" "$tag" || failures=$((failures+1))
          done
        else
          # Single target
          test_entry "$1" || failures=1
        fi
      done
      [[ $failures -eq 0 ]] && return 0 || return 1
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
      run_susops help
      return 1
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  susops "$@"
fi