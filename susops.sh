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
  local -r SUSOPS_PROCESS_NAME_BASE="susops"
  local -r SUSOPS_SSH_PROCESS_NAME="$SUSOPS_PROCESS_NAME_BASE-ssh"

  local -r SUSOPS_PAC_UNIFIED_PROCESS_NAME="$SUSOPS_PROCESS_NAME_BASE-pac"
  local -r SUSOPS_PAC_LOOP_PROCESS_NAME="$SUSOPS_PAC_UNIFIED_PROCESS_NAME-loop"
  local -r SUSOPS_PAC_NC_PROCESS_NAME="$SUSOPS_PAC_UNIFIED_PROCESS_NAME-nc"

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

  # Run yq in-place
  read_config() {
    yq e "$1" "$cfgfile"
  }

  update_config() {
    yq e -i "$1" "$cfgfile";
  }

  # Default to first connection if none specified
  if [[ -z $conn_tag ]]; then
    conn_tag=$(read_config '.connections[0].tag')
    if [[ $conn_tag == "null" && $cmd != "add-connection" ]]; then
      echo "No connection specified and no default connection found."
      echo "Please add a connection using:
susops add-connection <tag> <ssh_host> [<socks_proxy_port>]
      "
      cmd="invalid-command" # shows help and returns 1
    fi
  fi

  # Initialize ports
  pac_port=$(read_config ".pac_server_port")
  ssh_host=$(read_config ".connections[] | select(.tag==\"$conn_tag\").ssh_host")

  # Get connection tags from the config file
  # If a specific connection is specified, return only that tag
  get_connection_tags() {
    # $1: force all
    local always_all=${1:-false}
    if $conn_specified && [[ $always_all == false ]]; then
      # If a specific connection is specified, return only that tag
      read_config ".connections[] | select(.tag==\"$conn_tag\").tag"
    else
      # Otherwise, return all connection tags
      read_config '.connections[].tag'
    fi
  }

  ###############################################################################
  # load_port  <key> [conn_tag]
  #
  # • key        – Key to read from the config file (e.g. "socks_proxy_port")
  # • conn_tag   – Connection tag (optional, defaults to the current connection)
  #
  # Returns     – Port number (or generates a random one if not set)
  #
  # Generates a random port number if the key is not already set in the config file.
  ##############################################################################
  load_port() {
    local key=$1 filter
    local conn_tag=${2:-$conn_tag}
    if [[ $key == "pac_server_port" ]]; then
      filter=".pac_server_port"
    else
      filter=".connections[] | select(.tag==\"$conn_tag\").$key"
    fi
    local cur=$(read_config "$filter" | head -1)
    if [[ $cur =~ ^[0-9]+$ ]] && [[ $cur -gt 0 ]]; then
      echo $cur
    else
      local port
      port=$(get_random_free_port)
      if [[ $key == pac_server_port ]]; then
        update_config ".pac_server_port = $port"
      else
        update_config ".connections[] |= (select(.tag==\"$conn_tag\") .${key} = $port)"
      fi
      echo $port
    fi
  }

  ##############################################################################
  # prune_and_add_entry  <new_entry>
  # For a wildcard or CIDR, delete narrower entries already covered.
  ##############################################################################
  prune_and_add_entry() {
    local entry="$1"

    # 1) Wildcard pruning (if any)
    if [[ $entry == *"*"* ]]; then
      # prune out any existing host with wildcard
      # get matching pac_hosts comma se-separated
      existing_hosts=$(read_config '.connections[].pac_hosts | map(select(. == "'"$entry"'")) | join(", ")' | tr -d '\n')
      if [[ -n $existing_hosts ]]; then
        update_config "del(.connections[].pac_hosts[] | select(.==\"$entry\"))"
        echo "Removed more narrow domains $existing_hosts"
      fi

    # 2) CIDR pruning (if any)
    elif [[ $entry =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ ]]; then
      local net=${entry%/*} bits=${entry#*/}
      # remove narrower CIDRs under the same connection
      read_config ".connections[] | select(.tag==\"$conn_tag\") .pac_hosts[]" \
      | while IFS= read -r line; do
        if [[ $line =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ ]] && [[ $line == */* ]]; then
          local lnet=${line%/*} lbits=${line#*/}
          if (( bits < lbits )) && [[ $net == "$lnet" ]]; then
            update_config "del(.connections[].pac_hosts[] | select(.==\"$line\"))"
            echo "Removed more narrow CIDR $line"
          fi
        fi
      done
    fi

    # 3) Append the new entry
    update_config ".connections[] |= (select(.tag==\"$conn_tag\") .pac_hosts += [\"$entry\"])"
  }

  ######################################################################
  # pac_entry_overlaps  <candidate>
  # Returns 0 (true) if candidate is already covered by an existing rule
  ######################################################################
  pac_entry_overlaps() {
    local candidate="$1"
    local line suffix

    # 1) Check for exact duplicate
    if read_config '.connections[].pac_hosts[]' | grep -Fxq "$candidate"; then
      return 0
    fi

    # 2) Existing wildcard covers the new literal/CIDR?
    #    (skip this check if the candidate itself is a wildcard)
    if [[ $candidate != *"*"* ]]; then
      while read -r line; do
        [[ $line == *"*"* ]] || continue
        suffix=${line#\*}
        if [[ $candidate == *"$suffix" ]]; then
          return 0
        fi
      done < <(read_config '.connections[].pac_hosts[]')
    fi

    # 3) CIDR containment: only reject if an EXISTING broader-or-equal CIDR covers the new one
    if [[ $candidate == */* ]]; then
      local net1 bits1 net2 bits2
      net1=${candidate%/*}; bits1=${candidate#*/}
      while read -r line; do
        [[ $line =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ ]] || continue
        net2=${line%/*}; bits2=${line#*/}
        # if existing mask is <= candidate mask AND same prefix, existing covers candidate
        if (( bits2 <= bits1 )) && [[ ${net1%%.*} == "${net2%%.*}" ]]; then
          return 0
        fi
      done < <(read_config '.connections[].pac_hosts[]')
    fi

    # 4) Otherwise: no overlap
    return 1
  }

  ##############################################################################
  # cidr_to_netmask  <bits>
  # Converts /8 /16 /24 (and any 0-32) into dotted-decimal netmask.
  ##############################################################################
  cidr_to_netmask() {
    local bits=$1 mask="" i
    for i in {0..3}; do
      local n=$(( bits > 7 ? 8 : bits ))
      mask+=$(( 256 - 2**(8-n) ))
      bits=$(( bits-8 > 0 ? bits-8 : 0 ))
      [[ $i -lt 3 ]] && mask+=.
    done
    echo "$mask"
  }


  # (Re)generate unified PAC file with rules for all connections
  write_pac_file() {
    {
      echo 'function FindProxyForURL(url, host) {'
      while IFS= read -r tag; do
        local socks_proxy_port
        socks_proxy_port=$(read_config ".connections[] | select(.tag==\"$tag\").socks_proxy_port")

        read_config ".connections[] | select(.tag==\"$tag\") | .pac_hosts[]" |
        while read -r entry; do
          if [[ $entry == *"*"* ]]; then
            # wildcard – use shExpMatch
            echo "  if (shExpMatch(host, '$entry')) return 'SOCKS5 127.0.0.1:$socks_proxy_port';"
          elif [[ $entry =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ ]]; then
            # CIDR – split net/mask
            net=${entry%/*}; bits=${entry#*/}
            mask=$(cidr_to_netmask "$bits")
            echo "  if (isInNet(host, '$net', '$mask')) return 'SOCKS5 127.0.0.1:$socks_proxy_port';"
          else
            # plain host or exact IP
            echo "  if (host == '$entry' || dnsDomainIs(host, '.$entry')) return 'SOCKS5 127.0.0.1:$socks_proxy_port';"
          fi
        done
      done < <(get_connection_tags true)
      echo '  return "DIRECT";'
      echo '}'
    } > "$pacfile"
  }

  ##############################################################################
  # build_args  <key> <flag> [conn_tag]
  #
  # • key        – "local"  ⇒ -L style   (bind on client)
  #                "remote" ⇒ -R style   (bind on server)
  # • flag       – The SSH flag to emit  ("-L" or "-R")
  # • conn_tag   – Connection tag (optional; defaults to $conn_tag)
  #
  # Returns      – Array of arguments ready to splice into an ssh command
  ##############################################################################
  build_args() {
    local key=$1 flag=$2 conn_tag=${3:-$conn_tag}
    local args=()

    # jq prints either 4 fields (new schema) or 2 fields (old schema); we normalise to 4.
    while IFS=' ' read -r src_addr src_port dst_addr dst_port; do
      # Trailing fields may be empty (old schema) – convert on-the-fly.
      if [[ -z $dst_addr || -z $dst_port ]]; then
        # Legacy "src dst" line: assume loopback for both addresses
        src_port=$src_addr
        src_addr="localhost"
        dst_port=$dst_addr
        dst_addr="localhost"
      fi
      [[ -z $src_port || -z $dst_port ]] && continue  # still malformed? skip.

      args+=("$flag" "${src_addr}:${src_port}:${dst_addr}:${dst_port}")
    done < <(
      read_config '
        .connections[]
        | select(.tag == "'"$conn_tag"'")
        | (.forwards.'"$key"' // [])[]
        | [
              (.src_addr // "localhost"),
              (.src_port // .src | tostring),
              (.dst_addr // "localhost"),
              (.dst_port // .dst | tostring)
            ] | join(" ")
      ' "$cfgfile"
    )

    echo "${args[@]}"
  }

  # Align printf output for better readability
  align_printf() {
    local format=$1; shift
    local args=("$@")
    printf "%-25s $format\n" "${args[@]}"
  }

  ##############################################################################
  # is_running  <proc-pattern> [description] [print?] [port] [extra] [exact?]
  #
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
      if [[ $do_print == true ]]; then
        # Build “PID 123 456” or “PIDs 123 456”
        local list
        list=$(printf '%s\n' "$pids" | awk '{print $1}' | xargs)
        local how_many
        how_many=$(wc -w <<< "$list")
        local label="PID"
        [[ $how_many -gt 1 ]] && label="PIDs"

        if [[ -n $extra ]]; then
          align_printf "✅ running (%s %s%s%s)" "$desc:" "$label" "$list" "${port:+, port $port}" ", $extra"
        else
          align_printf "✅ running (%s %s%s)" "$desc:" "$label" "$list" "${port:+, port $port}"
        fi
      fi
      return 0
    fi

    # --- Not running ---------------------------------------------------------
    [[ $do_print == true ]] && align_printf "⚠️ not running" "$desc:"
    return 1
  }

  ##############################################################################
  # stop_by_name  <proc-pattern> <label> [keep_ports] [tag] [exact?]
  #
  # • proc-pattern – Pattern for pgrep to match processes.
  # • label        – Human-readable label (optional).
  # • keep_ports   – If "true", do not reset socks_proxy_port (default: false).
  # • tag          – Connection tag for port reset (optional).
  # • exact?       – "true" for exact match, "false" for pattern match (default: false).
  #
  # Kills all matching PIDs (SIGTERM), prints status, and resets port unless keep_ports is true.
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
        update_config "(.connections[] | select(.tag==\"$tag\")).socks_proxy_port = 0"
      fi

      align_printf "🛑 stopped" "${label:-Service}:"
      return 0
    fi

    align_printf "⚠️ not running" "${label:-Service}:"
    return 1
  }

  ############################################################################
  # test_entry  <target> [conn_tag]
  #
  # • target     – Host or port to test (e.g. localhost:8080 or example.com)
  # • conn_tag   – Connection tag (optional, defaults to the current connection)
  #
  # Test connectivity to a target through the SOCKS proxy.
  # If the target is a port, it will be tested as a local or remote forward.
  # If the target is a hostname, it will be tested through the SOCKS proxy.
  ############################################################################
  test_entry() {
    local target=$1
    local conn_tag=${2:-$conn_tag}
    local label=${3:-""}

    local ssh_host socks_port
    ssh_host=$(read_config ".connections[] | select(.tag==\"$conn_tag\").ssh_host")
    socks_port=$(read_config ".connections[] | select(.tag==\"$conn_tag\").socks_proxy_port")

    if [[ $target =~ ^[0-9]+$ ]]; then
      # Target looks like a port → could be local or remote
      if read_config ".connections[] | select(.tag==\"$conn_tag\").forwards.local[]?
               | select((.src // .src_port) == $target)" | grep -q . >/dev/null; then
        # Local forward exists: test localhost:src
        $verbose && echo "Testing local forward $target on localhost"
        if curl -s --max-time 5 "http://localhost:$target" >/dev/null 2>&1; then
          align_printf "✅ local:%s (localhost:%s → %s:%s)" "$label" \
                 "$target" "$target" "$ssh_host" \
                 "$(read_config '.forwards.local[] | select((.src // .src_port)=='"$target"') | (.dst // .dst_port)' \
                         <<<"$(read_config '.connections[] | select(.tag=="'"$conn_tag"'")')")"
          return 0
        else
          align_printf "❌ localhost:%s unreachable" "$label" "$target"
          return 1
        fi
      elif read_config ".connections[] | select(.tag==\"$conn_tag\").forwards.remote[]?
                 | select((.src // .src_port) == $target)" | grep -q . >/dev/null; then
        # Remote forward exists: test via ssh on remote side
        $verbose && echo "Testing remote forward $target on $ssh_host:$target"
        if ssh "$ssh_host" curl -s --max-time 5 "http://localhost:$target" >/dev/null 2>&1; then
          align_printf "✅ remote:%s (%s:%s → localhost:%s)" "$label" \
                 "$target" "$ssh_host" "$target" \
                 "$(read_config '.forwards.remote[] | select((.src // .src_port)=='"$target"') | (.dst // .dst_port)' \
                         <<<"$(read_config '.connections[] | select(.tag=="'"$conn_tag"'")')")"
          return 0
        else
          align_printf "❌ $ssh_host:%s unreachable" "$label" "$target"
          return 1
        fi
      else
        align_printf "❌ Port %s not found in forwards" "$label" "$target"
        return 1
      fi
    else
      if [[ $target == *"*"* ]] || [[ $target =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ ]]; then
        align_printf "⚠️%s skipped" "$label" "$target"
      elif curl -s -k --max-time 5 \
             --proxy "socks5h://127.0.0.1:$socks_port" \
             "https://$target" >/dev/null 2>&1; then
        align_printf "✅ %s via SOCKS" "$label" "$target"
        return 0
      else
        align_printf "❌ %s via SOCKS" "$label" "$target"
        return 1
      fi
    fi
  }

  # Validate if a port is in the range 1-65535
  validate_port_in_range() {
    # $1: port
    [[ $1 =~ ^[0-9]+$ && $1 -ge 1 && $1 -le 65535 ]]
  }

  # Check if exact local/remote forward rule exists
  check_exact_rule() {
    # $1: src, $2: dst, $3: type (local|remote)
    read_config ".connections[].forwards.$3[] | select((.src // .src_port)==\"$1\" and (.dst // .dst_port)==\"$2\")" | grep -q . && return 0
    return 1
  }

  # Check if a src port is configured for given type
  check_port_source() {
    # $1: port, $2: type (local|remote)
    read_config ".connections[].forwards.$2[] | select((.src // .src_port)==\"$1\")" | grep -q . && return 0
    return 1
  }

  # Check if a dst port is configured for given type
  check_port_target() {
    # $1: port, $2: type (local|remote)
    read_config ".connections[].forwards.$2[] | select((.dst // .dst_port)==\"$1\")" | grep -q . && return 0
    return 1
  }

  get_random_free_port() {
    local port raw
    while true; do
      raw=$(head -c2 /dev/random | od -An -tu2 | tr -d ' ')
      port=$(( raw % 16384 + 49152 ))
      if ! check_port_in_use "$port"; then
        echo "$port"
        return
      fi
    done
  }

  # Check if a port is in use on localhost or remote host
  check_port_in_use() {
    # $1: port, $2: host (optional, defaults to localhost)
    local port=$1 host=${2:-localhost}
    if [[ "$host" == localhost ]]; then
      lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1
    else
      ssh "$host" lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1
    fi
  }

  # Replace spaces with hyphens, remove leading/trailing whitespace
  normalize_process_name() {
    # $1: process name
    echo "$1" | xargs | tr ' ' '-'
  }

  start_susops() {
    # Usage: start [SSH_HOST] [SOCKS_PORT] [PAC_PORT]
    #
    # • SSH_HOST    – SSH host to connect to (overrides config.yaml)
    # • SOCKS_PORT  – Port for the SOCKS proxy (overrides config.yaml)
    # • PAC_PORT    – Port for the PAC server (overrides config.yaml)
    [[ -n $1 ]] && ssh_host=$1 && update_config   "(.connections[] | select(.tag==\"$conn_tag\")).ssh_host = \"$ssh_host\""
    [[ -n $2 ]] && socks_port=$2 && update_config "(.connections[] | select(.tag==\"$conn_tag\")).socks_proxy_port = $socks_port"
    [[ -n $1 ]] || [[ -n $2 ]] && stop_by_name "$(normalize_process_name "$SUSOPS_SSH_PROCESS_NAME-$conn_tag")" "SOCKS5 proxy [$conn_tag]" true

    [[ -n $3 ]] && pac_port=$3 && update_config   ".pac_server_port = $pac_port" && stop_by_name "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" "PAC server" true

    while IFS= read -r tag; do
      ssh_host=$(read_config ".connections[] | select(.tag==\"$tag\").ssh_host")
      # Ensure ephemeral port is set
      socks_port=$(load_port "socks_proxy_port" "$tag")

      # Start SOCKS proxy for chosen connection
      local process_name
      process_name=$(normalize_process_name "$SUSOPS_SSH_PROCESS_NAME-$tag")
      if is_running "$process_name" >/dev/null; then
        is_running "$process_name" true true "SOCKS5 proxy [$tag]" "$socks_port" "SSH host $ssh_host"
      else
        local_args=$(build_args "local" "-L" "$tag")
        remote_args=$(build_args "remote" "-R" "$tag")

        common_flags=(
          -N                           # no remote shell
          -T                           # disable pty
          -D "$socks_port"             # start with SOCKS
          -o ExitOnForwardFailure=yes  # exit if port forwarding fails
          -o ServerAliveInterval=30    # send keepalive every 30 seconds
          -o ServerAliveCountMax=3     # exit after 3 failed keepalives
          "${local_args[@]}"
          "${remote_args[@]}"
          "$ssh_host"
        )

        if command -v autossh &>/dev/null; then
          ssh_binary=(autossh -M 0)
        else
          $verbose && echo "autossh not found, falling back to ssh"
          ssh_binary=(ssh)
        fi

        inner_cmd=( exec -a "$process_name" "${ssh_binary[@]}" "${common_flags[@]}" )
        nohup bash -c "${inner_cmd[*]}" </dev/null >/dev/null 2>&1 &
        process_pid=$!

        if $verbose; then
          quoted_inner=$(IFS=' '; echo "${inner_cmd[*]}" | tr -s ' ')
          full_cmd="nohup bash -c '$quoted_inner' </dev/null >/dev/null 2>&1 &"
          echo "Full SSH command: $full_cmd"
        fi

        align_printf "🚀 started (PID %s, port %s, SSH host %s)" "SOCKS5 proxy [$tag]:" "$process_pid" "$socks_port" "$ssh_host"
      fi
    done < <(get_connection_tags)

    # persist changes for ephemeral ports and given arguments
    write_pac_file

    # Only start PAC server if not already running. Ensure ephemeral port is set
    local pac_port
    pac_port=$(load_port "pac_server_port")
    if is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" false >/dev/null; then
      is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" false true "PAC server" "$pac_port" "URL http://localhost:$pac_port/susops.pac"
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
  }

  stop_susops() {
    # Usage: susops stop [--keep-ports] [--force]
    #
    # • --keep-ports keeps the ports in config.yaml unchanged; otherwise the
    #   stopped connection’s socks_proxy_port is reset to 0.
    # • --force stops all connections and the PAC server no matter what's currently in the config
    local keep_ports=false
    local force=false
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --keep-ports) keep_ports=true; shift ;;
        --force) force=true; shift ;;
        *) shift ;;
      esac
    done

    if $force; then
      # Stop all connections and the PAC server
      pkill -f "$SUSOPS_SSH_PROCESS_NAME"
      pkill -f "$SUSOPS_PAC_UNIFIED_PROCESS_NAME"
      return 0
    fi

    while IFS= read -r tag; do
      local process_name
      process_name=$(normalize_process_name "$SUSOPS_SSH_PROCESS_NAME-$tag")
      stop_by_name "$process_name" "SOCKS5 proxy [$tag]" "$keep_ports" "$tag" true
    done < <(get_connection_tags)

    # Stop the PAC server if no other connections are running
    if ! pgrep -f $SUSOPS_SSH_PROCESS_NAME >/dev/null; then
      stop_by_name "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" "PAC server" true # keep port the same no matter if $keep_ports is set
    fi

    return 0
  }

  restart_susops() {
    # Usage: susops restart
    #
    # Restart the SOCKS proxy and PAC server without changing the ports.
    stop_susops --keep-ports --force
    start_susops
  }

  add() {
    local process_name
    process_name=$(normalize_process_name "$SUSOPS_SSH_PROCESS_NAME-$conn_tag")

    case "$1" in
      -l)
        local lport=$2                       # LOCAL_PORT  (field-2 of -L)
        local rport=$3                       # REMOTE_PORT (field-4 of -L)
        local tag=${4:-""}                   # human label
        local local_bind=${5:-"localhost"}   # field-1  of -L (bind addr on *your* host)
        local remote_bind=${6:-"localhost"}  # field-3  of -L (target addr on SSH server)

        # --------------------------------------------------------------------------- #
        [[ $lport && $rport ]] || {
          echo "Usage: susops add -l LOCAL_PORT REMOTE_PORT [TAG] [LOCAL_BIND] [REMOTE_BIND]"
          echo "Map a port from \${LOCAL_BIND:-localhost} to a remote server address"
          return 1
        }

        [[ -z $tag || $tag =~ ^[[:space:]]+$ ]] && tag="$lport"
        tag=$(echo "$tag" | xargs)

        # ── sanity checks ─────────────────────────────────────────────────────────── #
        if ! validate_port_in_range "$lport"; then
          echo "LOCAL_PORT must be between 1 and 65535"
          return 1
        elif ! validate_port_in_range "$rport"; then
          echo "REMOTE_PORT must be between 1 and 65535"
          return 1
        elif check_exact_rule "$lport" "$rport" "local"; then
          echo "Local forward ${local_bind}:${lport} → $ssh_host:${rport} already exists"
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
          echo "Local port ${lport} is already in use"
          return 1
        fi

        update_config ".connections[]
          |= (select(.tag==\"$conn_tag\")
              .forwards.local += [{
                \"tag\":      \"$tag\",
                \"src_addr\": \"$local_bind\",
                \"src_port\": $lport,
                \"dst_addr\": \"$remote_bind\",
                \"dst_port\": $rport
              }])"

        align_printf \
          "✅ Added local forward [${tag}] ${local_bind}:${lport} → ${ssh_host}:${remote_bind}:${rport}" \
          "Connection [$conn_tag]:"

        is_running "$process_name" && echo "Restart proxy to apply"
        return 0
        ;;

      -r)
        local rport=$2                      # REMOTE_PORT  (bind port on server)
        local lport=$3                      # LOCAL_PORT   (target port on client)
        local tag=${4:-""}                  # human label
        local remote_bind=${5:-"localhost"} # field-1 of -R (bind addr on server)
        local local_bind=${6:-"localhost"}  # field-3 of -R (target addr on client)

        [[ $rport && $lport ]] || {
          echo "Usage: susops add -r REMOTE_PORT LOCAL_PORT [TAG] [REMOTE_BIND] [LOCAL_BIND]"
          echo "Map a port from \${REMOTE_BIND:-localhost} on the server to \${LOCAL_BIND:-localhost} on your machine"
          return 1
        }

        [[ -z $tag || $tag =~ ^[[:space:]]+$ ]] && tag="$rport"
        tag=$(echo "$tag" | xargs)  # trim

        # ── sanity checks ─────────────────────────────────────────────────────────── #
        if ! validate_port_in_range "$rport"; then
          echo "REMOTE_PORT must be between 1 and 65535"
          return 1
        elif ! validate_port_in_range "$lport"; then
          echo "LOCAL_PORT must be between 1 and 65535"
          return 1
        elif check_exact_rule "$rport" "$lport" "remote"; then
          echo "Remote forward ${ssh_host}:${rport} → ${local_bind}:${lport} already exists"
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
          echo "Remote port ${rport} is already in use on ${ssh_host} (${remote_bind})"
          return 1
        fi

        update_config ".connections[]
          |= (select(.tag==\"$conn_tag\")
              .forwards.remote += [{
                \"tag\":      \"$tag\",
                \"src_addr\": \"$remote_bind\",
                \"src_port\": $rport,
                \"dst_addr\": \"$local_bind\",
                \"dst_port\": $lport
              }])"

        align_printf \
          "✅ Added remote forward [${tag}] ${ssh_host}:${remote_bind}:${rport} → ${local_bind}:${lport}" \
          "Connection [$conn_tag]:"

        is_running "$process_name" && echo "Restart proxy to apply"
        return 0
        ;;

      *)
        local entry=$1
        [[ $entry ]] || { echo "Usage: susops add [HOST|WILDCARD|CIDR]"; return 1; }

        # On URL, strip scheme + path, otherwise leave CIDRs intact
        if [[ $entry == *"://"* ]]; then
          # remove scheme:// and any trailing path
          entry=${entry#*://}
          entry=${entry%%/*}
        fi

        # Validate pattern
        if ! [[ $entry == *"*"* \
             || $entry =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ \
             || $entry =~ ^[A-Za-z0-9.-]+$ ]]; then
          echo "Error: unsupported host pattern '$entry'"
          return 1
        fi

        # Abort if truly duplicate; otherwise clean narrower ones
        if pac_entry_overlaps "$entry"; then
          echo "Error: PAC entry '$entry' already exists or is covered"
          return 1
        fi

        # prune and add (handles both wildcard & CIDR)
        prune_and_add_entry "$entry"

        write_pac_file
        align_printf "✅ Added $entry" "Connection [$conn_tag]:"

        # Connectivity test only for literal host / IP
        if [[ $entry != *"*"* && $entry != */* ]]; then
          is_running "$process_name" && test_entry "$entry" "$conn_tag" "Connectivity check:"
        fi
        echo "Please reload your browser proxy settings."
        return 0
    esac
  }

  rm() {
    local process_name
    process_name=$(normalize_process_name "$SUSOPS_SSH_PROCESS_NAME-$conn_tag")
    case "$1" in
      -l)
        local lport=$2
        [[ $lport ]] || { echo "Usage: susops rm -l LOCAL_PORT"; return 1; }
        if check_port_source "$lport" "local"; then
          update_config "del(.connections[].forwards.local[] | select((.src // .src_port)==$lport))"
          echo "Removed local forward $lport"
          is_running "$process_name" && echo "Restart proxy to apply"
          return 0
        else
          echo "No local forward for $lport"
          return 1
        fi
        ;;

      -r)
        local rport=$2
        [[ $rport ]] || { echo "Usage: susops rm -r REMOTE_PORT"; return 1; }
        if check_port_source "$rport" "remote"; then
          update_config "del(.connections[].forwards.remote[] | select((.src // .src_port)==$rport))"
          echo "Removed remote forward $ssh_host:$rport"
          is_running "$process_name" && echo "Restart proxy to apply"
          return 0
        else
          echo "No remote forward for $ssh_host:$rport"
          return 1
        fi
        ;;

      *)
        local host=$1 existing_hosts
        [[ $host ]] || { echo "Usage: rm [HOST] [-l LOCAL_PORT] [-r REMOTE_PORT]"; return 1; }

        existing_hosts=$(read_config '.connections[].pac_hosts | map(select(. == "'"$host"'")) | join(", ")' | tr -d '\n')

        if [[ -n $existing_hosts ]]; then
          update_config "del(.connections[].pac_hosts[] | select(.==\"$host\"))"
          write_pac_file
          echo "Removed $existing_hosts"
          is_running "$process_name" && echo "Please reload your browser proxy settings."
          return 0
        else
          echo "$host not found"
          if [[ $host =~ ^[0-9]+$ ]]; then echo "Use \"susops -l LOCAL_PORT\" OR \"susops -r REMOTE_PORT\" to remove a forwarded port"; fi
          return 1
        fi
        ;;
    esac
  }

  ##############################################################################
  # susops share  <file> <password> [port]
  #
  # • Starts a one-shot netcat server on 127.0.0.1:<port>.
  # • Peers must send <password>\n as the very first line.
  # • Upon a match the server replies “OK\n” **in clear text**, then
  #   streams  gzip | openssl enc -aes-256-ctr -salt -pbkdf2  data.
  # • If the password is wrong they receive “Unauthorized\n”.
  ##############################################################################
  share_file() {
    local file=$1 pass=$2 req_port=$3
    [[ -r $file && -n $pass ]] || {
      echo "Usage: susops share <file> <password> [port]"
      return 1
    }

    # Pick an unoccupied high port if none supplied
    local port=$req_port
    if [[ -z $port ]]; then
      port=$(get_random_free_port)
    elif ! validate_port_in_range "$port"; then
      echo "Error: port must be a valid port in range 1 to 65535"
      return 1
    elif check_port_in_use "$port"; then
      echo "Error: port $port is already in use"
      return 1
    fi
    [[ $port ]] || { echo "❌ No free port found"; return 1; }

    echo "🔐 Serving '$file' on http://127.0.0.1:$port (Ctrl+C to stop)"

    # 1 Ensure the reverse-forward exists (localhost:port on proxy → localhost:port here)

    add "-r" "$port" "$port" "share-$port" "localhost" "localhost" || return 1
    restart_susops

    # 2 Loop, handling one client at a time
    running=true
    trap "running=false" SIGINT

    # 3 Compress and encrypt the file once
    local contentfile
    contentfile="$(mktemp)"
    gzip -c "$file" | openssl enc -aes-256-ctr -salt -pbkdf2 -pass pass:"$pass" > "$contentfile"
    length=$(wc -c <"$contentfile")

    $verbose && echo "Created content file: $contentfile"

    while $running; do
      echo "Waiting for client connection on port $port..."
      # launch nc as a coprocess to allow read & write to the same socket
      coproc NC_SHARE { nc -l "$port"; }

      if [[ $? -ne 0 ]]; then
        echo "Error: Failed to start share on port $port"
        break
      fi

      # 1) read headers until blank line, capture Basic auth
      local auth header
      while IFS=$'\r\n' read -r header <&"${NC_SHARE[0]}"; do
        [[ -z $header ]] && break
        if [[ $header =~ ^Authorization:\ Basic\ (.+)$ ]]; then
          auth=${BASH_REMATCH[1]}
        fi
      done

      # break early to prevent "ambiguous redirect" file errors as NC_SHARE has been closed
      if ! $running; then
        echo "Exiting share server..."
        break
      fi

      # 2) validate creds
      local decoded
      decoded=$(printf '%s' "$auth" | base64 -d 2>/dev/null)
      if [[ ":$pass" == "$decoded" ]]; then
        echo "Authorized access from $(printf '%s' "$auth" | base64 -d 2>/dev/null)"
        # 200 OK + headers
        {
          printf 'HTTP/1.1 200 OK\r\n'
          printf 'Content-Type: application/octet-stream\r\n'
          printf 'Content-Length: %s\r\n' "$length"
          printf 'Content-Disposition: attachment; filename="%s"\r\n' "$(basename "$file")"
          printf 'Connection: close\r\n'
          printf '\r\n'
          cat "$contentfile"
        } >&"${NC_SHARE[1]}"
      else
        echo "Unauthorized access attempt $(printf '%s' "$auth" | base64 -d 2>/dev/null)"
        # 401 challenge
        {
          printf 'HTTP/1.1 401 Unauthorized\r\n'
          printf 'WWW-Authenticate: Basic realm="susops share"\r\n'
          printf 'Content-Length: 0\r\n'
          printf '\r\n'
        } >&"${NC_SHARE[1]}"
      fi

      # clean up this coprocess
      exec {NC_SHARE[0]}>&-   # close read end
      exec {NC_SHARE[1]}>&-   # close write end
      wait "$NC_SHARE_PID"    # reap the nc process before looping again
    done

    unlink "$contentfile" || echo "❌ Could not unlink encrypted file '$file.encrypted'"

    rm "-r" "$port" || return 1
    restart_susops

    echo "Exited."
  }

  ##############################################################################
  # susops fetch <port> <password> [outfile]
  #
  # • <port>                Port the sharer told you (the HTTP listener)
  # • <password>            Password to authenticate against the share server
  # • [outfile]             If not set use response Content-Disposition filename
  ##############################################################################
  download_file() {
    local port=$1 pass=$2 outfile=$3
    [[ $port && $pass ]] || {
      echo "Usage: susops fetch <port> <password> [outfile]"
      return 1
    }

    # ensure the SSH local-forward exists
#    if ! check_exact_rule "$port" "$port" "local" "$conn_tag" >/dev/null; then
#      add -l "$port" "$port" "fetch-$port" "localhost" "localhost" \
#        || { echo "❌ could not add local forward"; return 1; }
#      restart_susops
#    fi

    # fetch, decrypt, decompress
    echo "🔽 Downloading via HTTP on localhost:$port …"

    local headerfile contentfile
    headerfile="$(mktemp)"
    contentfile="$(mktemp)"

    $verbose && echo "Using header file: $headerfile"
    $verbose && echo "Using content file: $contentfile"

    if ! curl -s --fail --dump-header "$headerfile" \
      --user ":$pass" \
      http://localhost:"$port" \
      -o "$contentfile"
    then
      echo "❌ Download failed or unauthorized"
      unlink "$headerfile"
      unlink "$contentfile"
      return 1
    fi

    openssl enc -d -aes-256-ctr -pbkdf2 -pass pass:"$pass" \
      -in "$contentfile" | gunzip -c > "$contentfile.decrypted"

    mv "$contentfile.decrypted" "$contentfile"

    # use outfile as filename, if not set use content disposition, if not set use date
    if [[ -z "$outfile" ]]; then
      outfile=$(grep -i '^Content-Disposition:' "$headerfile" \
        | sed -n 's/.*filename="\([^"]*\)".*/\1/p')
      if [[ -z "$outfile" ]]; then
        outfile="download.$(date +%s)"
      fi
    fi

    mv "$contentfile" "$outfile" \
      && echo "✅ Saved to $outfile" \
      || { echo "❌ Could not save to $outfile"; return 1; }
  }

  print_help() {
    cat << EOF
Usage: susops [-v|--verbose] [-c|--connection TAG] COMMAND [ARGS]
Commands:
  add-connection TAG SSH_HOST [SOCKS_PORT]                                        add a new connection
  rm-connection  TAG                                                              remove a connection
  add [HOST|WILDCARD|CIDR]                                                        add hostname or port forward, schema bind → host
      [-l LOCAL_PORT REMOTE_PORT [TAG] [LOCAL_BIND] [REMOTE_BIND]]
      [-r REMOTE_PORT LOCAL_PORT [TAG] [LOCAL_BIND] [REMOTE_BIND]]
  rm  [HOST] [-l LOCAL_PORT] [-r REMOTE_PORT]                                     remove hostname or port forward
  start   [SSH_HOST] [SOCKS_PORT] [PAC_PORT]                                      start proxy and PAC server
  stop    [--keep-ports] [--force]                                                stop proxy and server (if no other proxies are running)
  restart                                                                         stop and start (preserves ports)
  ps                                                                              show status, ports, and forwards
  ls                                                                              output current config
  config                                                                          open config file in an editor
  reset   [--force]                                                               remove all files and configs
  test    --all|TARGET                                                            test connectivity
  chrome                                                                          launch Chrome with proxy
  chrome-proxy-settings                                                           open Chrome proxy settings
  firefox                                                                         launch Firefox with proxy
  share   <file> <password> [port]                                                securely share a file, serves encrypted content
  fetch   <port> <password> [outfile]                                             download a file shared via susops share
  help, --help, -h                                                                show this help message
Options:
  -v, --verbose                                                                   enable verbose output
  -c, --connection TAG                                                            specify connection tag
EOF
  }

  case $cmd in
    help|--help|-h)
      # Usage: susops help
      #
      # Show help message with usage instructions and available commands.
      # This is the default command if no other command is specified.
      print_help
      ;;

    add-connection)
      # Usage: susops add-connection TAG SSH_HOST [SOCKS_PORT]
      #
      # • TAG         – Connection tag (must not contain whitespace)
      # • SSH_HOST    – SSH host to connect to
      # • SOCKS_PORT  – Port for the SOCKS proxy (default: ephemeral port)

      local tag=$1
      local ssh_host=${2:-""}
      local socks_proxy_port=$3

      [[ -z $tag || $tag =~ ^[[:space:]]+$ ]] && { echo "Usage: susops add-connection TAG SSH_HOST [SOCKS_PORT]"; echo "TAG must not contain a whitespace"; return 1; }
      tag=$(echo "$tag" | xargs)

      # Abort if tag already present
      if read_config ".connections[] | select(.tag == \"$tag\")" | grep -q . >/dev/null; then
        echo "Error: connection '$tag' already exists"
        return 1
      fi

      [[ -z $ssh_host ]] && { echo "Error: SSH host is required"; return 1; }

      if [[ -z $socks_proxy_port ]]; then
        socks_proxy_port=$(load_port "socks_proxy_port" "$tag")
      elif ! validate_port_in_range "$socks_proxy_port"; then
        echo "Error: socks_proxy_port must be a valid port in range 1 to 65535"
        return 1
      elif read_config ".connections[] | select(.socks_proxy_port == $socks_proxy_port)" | grep -q . >/dev/null; then
        echo "Error: socks_proxy_port $socks_proxy_port is already in use by another connection"
        return 1
      fi

      local port_temp
      port_temp=$(get_random_free_port)

      ssh -q \
          -f \
          -o BatchMode=yes \
          -o ConnectTimeout=5 \
          -o ExitOnForwardFailure=yes \
          -N -T \
          -L ${port_temp}:127.0.0.1:22 \
          "$ssh_host"

      # Test ssh connection to host
      if [ $? -ne 0 ]; then
        echo "Error: SSH proxy test to host '$ssh_host' failed"
        return 1
      fi

      sleep 1
      kill "$(lsof -tiTCP:${port_temp} -sTCP:LISTEN)" 2>/dev/null

      # Add connection to config file
      update_config ".connections += [{
        \"tag\": \"$tag\",
        \"ssh_host\": \"$ssh_host\",
        \"socks_proxy_port\": $socks_proxy_port,
        \"forwards\": {\"local\": [], \"remote\": []},
        \"pac_hosts\": []
      }]"

      align_printf "✅ tested & added" "Connection [$tag]:"
      is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME"
      echo "Restart proxy to apply"
      ;;

    rm-connection)
      # Usage: susops rm-connection TAG
      #
      # • TAG – Connection tag to remove
      #
      # Remove a connection from the config file and stop the SOCKS proxy if running.
      # If the connection has hosts, the PAC file will be updated.

      local tag=$1
      [[ -z $tag ]] && { echo "Usage: susops rm-connection TAG"; return 1; }

      if ! read_config ".connections[] | select(.tag == \"$tag\")" | grep -q . >/dev/null; then
        align_printf "❌ not found" "Connection [$tag]:"
        return 1
      fi

      # Stop tunnel if still running
      local process_name
      process_name=$(normalize_process_name "$SUSOPS_SSH_PROCESS_NAME-$tag")
      stop_by_name "$process_name" "SOCKS5 proxy [$tag]" false "$tag" >/dev/null

      # check if connection has hosts
      local has_hosts
      has_hosts=$(read_config ".connections[] | select(.tag == \"$tag\") | .pac_hosts" | grep -q . >/dev/null)
      # delete connection
      update_config "del(.connections[] | select(.tag == \"$tag\"))"

      local hint=""
      if [[ $has_hosts ]]; then
        hint=". Please reload your browser proxy settings."
      fi

      align_printf "✅ stopped & removed $hint" "Connection [$tag]:"
      return 0
      ;;

    add)
      # Usage: susops add [HOST]                                                        – Add a hostname
      #                   [-l LOCAL_PORT REMOTE_PORT [TAG] [LOCAL_BIND] [REMOTE_BIND]]  – Add a local forward
      #                   [-r REMOTE_PORT LOCAL_PORT [TAG] [LOCAL_BIND] [REMOTE_BIND]]  – Add a remote forward

      add "$@"
      ;;



    rm)
      # Usage:
      #   susops rm [HOST] [-l LOCAL_PORT] [-r REMOTE_PORT]
      #
      # • HOST        – Hostname to remove from config and PAC file
      # • LOCAL_PORT  – Port to remove from local forward
      # • REMOTE_PORT – Port to remove from remote forward
      #

      rm "$@"
      ;;

    restart)
      restart_susops
      ;;

    start)
      start_susops "$@"
      ;;

    stop)
      stop_susops "$@"
      ;;

    ps)
      # Usage: susops ps
      #
      # • Lists the PAC server once.
      # • Then lists every configured connection, showing:
      #     – SOCKS PID(s)   – port   – SSH host
      # • Returns 0 if *all* expected services are running, 1 otherwise.
      stopped_count=0
      overall_count=0

      # 1. Iterate over connections
      while IFS= read -r tag; do
        local socks_port ssh_host
        socks_port=$(read_config ".connections[] | select(.tag==\"$tag\").socks_proxy_port")
        ssh_host=$(read_config ".connections[] | select(.tag==\"$tag\").ssh_host")

        # SOCKS / autossh status
        overall_count=$((overall_count+1))

        local process_name
        process_name=$(normalize_process_name "$SUSOPS_SSH_PROCESS_NAME-$tag")
        is_running "$process_name" true true "SOCKS5 proxy [$tag]" "$socks_port" \
                   "SSH host ${ssh_host:-<unset>}" || stopped_count=$((stopped_count+1))
      done < <(get_connection_tags)

      # 2. PAC server status (single global instance)
      overall_count=$((overall_count+1))
      is_running "$SUSOPS_PAC_UNIFIED_PROCESS_NAME" false true "PAC server" "$pac_port" \
                 "URL http://localhost:${pac_port}/susops.pac" || stopped_count=$((stopped_count+1))

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
      # Usage: susops ls
      #
      # • Lists the current configuration in YAML format.
      read_config "."
      ;;

    config)
      # Usage: susops config
      #
      # • Opens the configuration file in the default editor.
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

      # ensure all susops processes are stopped
      # do not use $SUSOPS_PROCESS_NAME_BASE here as this will also stop
      # - all browsers using the pac server url
      # - VCS applications

      pkill -f "$SUSOPS_SSH_PROCESS_NAME"
      pkill -f "$SUSOPS_PAC_UNIFIED_PROCESS_NAME"

      rm -rf "$workspace"
      echo "Removed workspace '$workspace' and all susops configuration."
      ;;

    test)
      # Usage: susops test --all|TARGET
      #
      # • --all   tests every pac_host, every local forward, and every remote
      #   forward for the *current* connection tag ($conn_tag).
      # • TARGET can be either a hostname in pac_hosts or a numeric port
      #   (local or remote forward).  Example:  susops --conn dev test 5432
      # • If TARGET is a port, it will be tested as both a local and remote
      #   forward.
      # • If TARGET is a hostname, it will be tested through the SOCKS proxy.
      #
      #  Exit status: 0 if every test passes, 1 otherwise.
      [[ $1 ]] || { echo "Usage: susops test --all|TARGET"; return 1; }

      local failures=0
      local stopped=0

      while IFS= read -r tag; do
        echo "----------------------------------------"
        echo "Testing connection '$tag'"
        # Pull runtime values for this connection

        local socks_port ssh_host
        socks_port=$(read_config ".connections[] | select(.tag==\"$conn_tag\").socks_proxy_port")
        ssh_host=$(read_config ".connections[] | select(.tag==\"$conn_tag\").ssh_host")

        # Ensure the SOCKS proxy for this connection is running
        local process_name
        process_name=$(normalize_process_name "$SUSOPS_SSH_PROCESS_NAME-$tag")
        if ! is_running "$process_name" true true "SOCKS5 proxy" "$socks_port" "SSH host ${ssh_host:-<unset>}"; then
          stopped=$((stopped+1))
          continue
        fi

        # Run tests

        if [[ $1 == --all ]]; then
          local first=true
          # 1) All PAC hosts
          while read -r host; do
            [[ $first == true ]] && echo "PAC hosts:" && first=false
            test_entry "$host" "$tag" || failures=$((failures+1))
          done < <(read_config ".connections[] | select(.tag==\"$tag\") | (.pac_hosts // [])[]")

          # 2) All local forwards (by src port)
          first=true
          while IFS= read -r port; do
            [[ $first == true ]] && echo "Local forwards:" && first=false
            test_entry "$port" "$tag" || failures=$((failures+1))
          done < <(read_config ".connections[]
              | select(.tag==\"$tag\")
              | (.forwards.local // [])[]
              | (.src // .src_port)")

          # 3) All remote forwards (by src port on remote)
          first=true
          while IFS= read -r port; do
            [[ $first == true ]] && echo "Remote forwards:" && first=false
            test_entry "$port" "$tag" || failures=$((failures+1))
          done < <(read_config ".connections[]
              | select(.tag==\"$tag\")
              | (.forwards.remote // [])[]
              | (.src // .src_port)")
        else
          # Single target
          test_entry "$1" || failures=1
        fi
      done < <(get_connection_tags)
      [[ $failures -eq 0 ]] && return 0 || return 1
      ;;

    chrome)
      # Usage: susops chrome
      #
      # • Launches Google Chrome with the PAC file as a proxy.
      open -a "Google Chrome" --args --proxy-pac-url="http://localhost:$pac_port/susops.pac"
      ;;

    chrome-proxy-settings)
      # Usage: susops chrome-proxy-settings
      #
      # • Opens the Chrome proxy settings page, click "Re-apply settings" to
      #   read the PAC file content and apply rules.
      open -a "Google Chrome" "chrome://net-internals/#proxy"
      ;;

    firefox)
      local PROFILE="$workspace/firefox_profile"
      mkdir -p "$PROFILE"
      printf 'user_pref("network.proxy.type", 2);\nuser_pref("network.proxy.autoconfig_url", "http://localhost:%s/susops.pac");' "$pac_port" > "$PROFILE/user.js"
      open -a "Firefox" --args -profile "$PROFILE" -no-remote
      ;;

    share)
      # Usage: susops share <file> <user> <password> [port]
      #
      # • <file>     – File to share
      # • <password> – Password for the file
      # • [port]     – Port to listen on (default: random free port)

      share_file "$@"
      ;;

    fetch)
      # Usage: susops fetch <port> <user> <password> [outfile]
      #
      # • <port>     – Port the sharer told you (the HTTP listener)
      # • <user>     – User for the file
      # • <password> – Password for the file
      # • [outfile]  – Where to write the file (default: download.<timestamp>)

      download_file "$@"
      ;;

    *)
      print_help
      return 1
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  susops "$@"
fi