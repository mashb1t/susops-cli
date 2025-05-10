#!/usr/bin/env bash

# susops with multi-connection YAML config and unified PAC file
susops() {
  set +m
  local -r workspace="."
  local -r cfgfile="$workspace/config.yaml"
  local -r pacfile="$workspace/susops.pac"

  local -r SUSOPS_PAC_LOOP_PROCESS_NAME="susops-pac-loop"
  local -r SUSOPS_PAC_NC_PROCESS_NAME="susops-pac-nc"
  local -r SUSOPS_PAC_UNIFIED_PROCESS_NAME="susops-pac"

  mkdir -p "$workspace"
  # Bootstrap config if missing
  if [[ ! -f "$cfgfile" ]]; then
    cat >"$cfgfile" <<EOF
pac_server_port: 0
connections:
  - tag: default
    ssh_host: ""
    socks_proxy_port: 0
    forwards:
      local: []
      remote: []
    pac_hosts: []
EOF
  fi

  # Parse global flags: --conn TAG, --verbose
  local verbose=false conn_tag="default"
  local args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v|--verbose) verbose=true; shift ;;
      --conn) conn_tag=$2; shift 2 ;;
      *) args+=("$1"); shift ;;
    esac
  done
  set -- "${args[@]}"

  # Default to first connection if none specified
  if [[ -z $conn_tag ]]; then
    conn_tag=$(yq e '.connections[0].tag' "$cfgfile")
  fi
  $verbose && echo "Using connection: $conn_tag"

  # If specified connection does not exist, append it
  local existing
  existing=$(yq e ".connections[] | select(.tag == \"$conn_tag\").tag" "$cfgfile")
  if [[ -z $existing || $existing == "null" ]]; then
    yq e -i ".connections += [{\"tag\": \"$conn_tag\", \"ssh_host\": \"\", \"socks_proxy_port\": 0, \"forwards\": {\"local\": [], \"remote\": []}, \"pac_hosts\": []}]" "$cfgfile"
    $verbose && echo "Added new connection '$conn_tag' to config file"
  fi

  # Helper: run yq in-place
  update_cfg() { yq e -i "$1" "$cfgfile"; }

  align_printf() {
    local format=$1; shift
    local args=("$@")
    printf "%-23s $format\n" "${args[@]}"
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
    local desc=${2:-Service}
    local do_print=${3:-false}
    local port=$4
    local extra=$5
    local exact=${6:-false}

    local pids

    if [[ $exact == true ]]; then
      # ^pattern$ anchors the full command line (pgrep -f)
      pids=$(pgrep -a -f "^${pattern}$" 2>/dev/null || :)
    else
      pids=$(pgrep -a -f "${pattern}"   2>/dev/null || :)
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
  # • label        – Human-readable label, e.g. "SOCKS5 proxy:"  (optional)
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
      pids=$(pgrep -a -f "^${pattern}$" 2>/dev/null || :)
    else
      pids=$(pgrep -a -f "${pattern}"   2>/dev/null || :)
    fi

    if [[ -n $pids ]]; then
      # Terminate every PID that is still alive
      for pid in $(printf '%s\n' "$pids" | awk '{print $1}'); do
        kill "$pid" 2>/dev/null
      done

      # zero out the socks_proxy_port unless user asked to keep
      if [[ ! $keep_ports && $tag ]]; then
        yq e -i "(.connections[] | select(.tag==\"$tag\")).socks_proxy_port = 0" "$cfgfile"
      fi

      align_printf "🛑 stopped" "${label:-Service}"
      return 0
    fi

    align_printf "⚠️ not running" "${label:-Service}"
    return 1
  }


  # Load or generate a port: global pac_server_port or per-connection socks_proxy_port
  load_port() {
    local key=$1 filter
    if [[ $key == pac_server_port ]]; then
      filter=".pac_server_port"
    else
      filter=".connections[] | select(.tag==\"$conn_tag\").$key"
    fi
    local cur=$(yq e "$filter" "$cfgfile" | head -1)  # Take only first value
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
    local key=$1 flag=$2 conn_tag=$3
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

  # Dispatch commands
  [[ $1 ]] || { susops help; return 1; }
  local cmd=$1; shift
  case "$cmd" in
    start)
      # Optionally override SSH host
      if [[ -n $1 ]]; then
        ssh_host=$1
        update_cfg "(.connections[] | select(.tag==\"$conn_tag\")).ssh_host = \"$ssh_host\""
      fi
      [[ -z $ssh_host ]] && { echo "Error: SSH host is required"; return 1; }

      # Start SOCKS proxy for chosen connection
      if ! pgrep -f "susops-ssh-$conn_tag" >/dev/null; then
        local_args=$(build_args local "-L")
        remote_args=$(build_args remote "-R")
        local ssh_cmd=(autossh -M 0 -N -T -D "$socks_port" "${local_args[@]}" "${remote_args[@]}" "$ssh_host")
        echo "SSH command to run: ${ssh_cmd[*]}"
        nohup bash -c "exec -a susops-ssh-$conn_tag ${ssh_cmd[*]}" </dev/null >/dev/null 2>&1 &
        echo "🚀 Started SOCKS5 proxy $conn_tag on port $socks_port"
      else
        echo "⚠️ SOCKS proxy already running for '$conn_tag'"
      fi

      # Start unified PAC server (one instance)
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
      # Usage:
      #   susops stop [--keep-ports] [TAG|all]
      #
      # • If TAG is omitted we stop the *current* connection (from --conn or
      #   $SUSOPS_CONNECTION).
      # • Pass “all” to stop every connection plus the PAC server.
      # • --keep-ports keeps the ports in config.yaml unchanged; otherwise the
      #   stopped connection’s socks_proxy_port is reset to 0.

      local keep_ports=false
      [[ $1 == '--keep-ports' ]] && keep_ports=true && shift

      local target="${1:-$conn_tag}"     # default to current connection tag

      if [[ $target == all ]]; then
        for tag in $(yq e '.connections[].tag' "$cfgfile"); do
          stop_by_name "susops-ssh-$tag" "SOCKS5 proxy [$tag]:" $keep_ports $tag
        done
      else
        stop_by_name "susops-ssh-$target" "SOCKS5 proxy [$target]:" $keep_ports $target
      fi

      # Stop the PAC server if no other connections are running
      if ! pgrep -f 'susops-ssh-' >/dev/null; then
        stop_by_name "susops-pac" "PAC server:" $keep_ports
      fi

      return 0
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

      ##################################################################
      # 1. Stop every running connection and PAC server (keep port
      #    values only so we don't spew 'not running' hints during stop)
      ##################################################################
      susops stop --keep-ports all

      ##################################################################
      # 2. Remove the entire workspace (config.yaml, pac file, port
      #    files, browser profiles …)
      ##################################################################
      rm -rf "$workspace"
      echo "Removed workspace ‘$workspace’ and all susops configuration."
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
      # 1. PAC server status (single global instance)
      ##################################################################
      local pac_port
      pac_port=$(yq e '.pac_server_port' "$cfgfile")
      overall_count=$((overall_count+1))
      is_running "susops-pac" "PAC server" true "$pac_port" \
                 "URL: http://localhost:${pac_port}/susops.pac" || stopped_count=$((stopped_count+1))

      ##################################################################
      # 2. Iterate over every connection
      ##################################################################
      for tag in $(yq e '.connections[].tag' "$cfgfile"); do
        local socks_port ssh_host
        socks_port=$(yq e ".connections[] | select(.tag==\"$tag\").socks_proxy_port" "$cfgfile")
        ssh_host=$(yq e ".connections[] | select(.tag==\"$tag\").ssh_host" "$cfgfile")

        # SOCKS / autossh status
        overall_count=$((overall_count+1))
        is_running "susops-ssh-${tag}" "SOCKS5 proxy [$tag]" true "$socks_port" \
                   "SSH host: ${ssh_host:-<unset>}" || stopped_count=$((stopped_count+1))
      done

      if [[ $stopped_count -eq 0 ]]; then
        return 0
      elif [[ $stopped_count -le $overall_count ]]; then
        return 1
      elif [[ $stopped_count -eq $overall_count ]]; then
        return 2
      else
        return 3
      fi
      ;;


    add-local)
      # Changed to SRC DST [TAG], disallow duplicate tags
      if [[ $# -lt 2 ]]; then
        echo "Usage: susops add-local SRC DST [TAG]"
        return 1
      fi
      local src=$1 dst=$2 tag
      if [[ $# -eq 3 ]]; then
        tag=$3
      else
        tag="$src"
      fi
      # Prevent duplicate local ports
#      if yq e ".connections[] | select(.tag==\"$conn_tag\").forwards.local[] | select(.src==\"$src\")" "$cfgfile" | grep -q "$src"; then
      if yq e ".connections[].forwards.local[] | select(.tag==\"$tag\" or .src==\"$src\")" "$cfgfile" | grep -q .; then
        echo "Error: local forward tag '$tag' or src '$src' already exists"
        return 1
      fi
      update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") .forwards.local += [{\"tag\": \"$tag\", \"src\": $src, \"dst\": $dst}])"
      echo "✅ Added local forward [${tag}] localhost:${src} → ${ssh_host}:${dst}"
      ;;

    rm-local)
      local sel=$1
      update_cfg "del(.connections[] | select(.tag==\"$conn_tag\").forwards.local[] | select(.tag==\"$sel\" or .src==$sel))"
      echo "🛑 Removed local forward '$sel'"
      ;;


    add-remote)
      # Changed to SRC DST [TAG], disallow duplicate tags
      if [[ $# -lt 2 ]]; then
        echo "Usage: susops add-remote SRC DST [TAG]"
        return 1
      fi
      local src=$1 dst=$2 tag
      if [[ $# -eq 3 ]]; then
        tag=$3
      else
        tag="$src"
      fi
      # Prevent duplicate tags
#      if yq e ".connections[] | select(.tag==\"$conn_tag\").forwards.remote[] | select(.tag==\"$tag\" or .src==\"$src\")" "$cfgfile" | grep -q .; then
      if yq e ".connections[].forwards.remote[] | select(.tag==\"$tag\" or .src==\"$src\")" "$cfgfile" | grep -q .; then
        echo "Error: remote forward tag '$tag' or src '$src' already exists"
        return 1
      fi
      update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") | .forwards.remote += [{\"tag\": \"$tag\", \"src\": $src, \"dst\": $dst}])"
      echo "✅ Added remote forward [${tag}] ${ssh_host}:${src} → localhost:${dst}"
      ;;

    rm-remote)
      local sel=$1
#      update_cfg "del(.connections[] | select(.tag==\"$conn_tag\").forwards.remote[] | select(.tag==\"$sel\" or .src==$sel))"
      update_cfg "del(.connections[].forwards.remote[] | select(.tag==\"$sel\" or .src==$sel))"
      echo "🛑 Removed remote forward '$sel'"
      ;;

    add-host)
      local host=$1
#      update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") .pac_hosts += [{host: \"$host\", tag: \"$tag\"}])"
#      update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") .pac_hosts += [{\"host\": \"$host\", \"tag\": \"$tag\"}])"
      if yq e ".connections[].pac_hosts[] | select(.==\"$host\")" "$cfgfile" | grep -q .; then
#      if yq e ".connections[] | select(.tag==\"$conn_tag\").pac_hosts[] | select(.==\"$host\")" "$cfgfile" | grep -q .; then
        echo "Error: PAC host '$host' already exists [$conn_tag]"
        return 1
      fi
      update_cfg ".connections[] |= (select(.tag==\"$conn_tag\") .pac_hosts += [\"$host\"])"
      write_pac_file

      echo "✅ Added PAC host $host [$conn_tag]"
      ;;

    rm-host)
      local sel=$1
#      update_cfg "del(.connections[] | select(.tag==\"$conn_tag\").pac_hosts[] | select(.host==\"$sel\" or .tag==\"$sel\"))"
#      update_cfg "del(.connections[] | select(.tag==\"$conn_tag\").pac_hosts[] | select(.==\"$sel\"))"
      # Check if sel is found
      if ! yq e ".connections[].pac_hosts[] | select(.==\"$sel\")" "$cfgfile" | grep -q . >/dev/null; then
        echo "Error: host '$sel' not found"
        return 1
      fi

      update_cfg "del(.connections[].pac_hosts[] | select(.==\"$sel\"))"
      write_pac_file
      echo "🛑 Removed PAC host '$sel'"
      ;;

    ls)
      yq e "." "$cfgfile"
      ;;

    open-config)
      open "$cfgfile"
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

      # Helper: single host/port test
      ############################################################
      test_entry() {
        local target=$1
        if [[ $target =~ ^[0-9]+$ ]]; then
          # Target looks like a port → could be local or remote
          if yq e ".connections[] | select(.tag==\"default\").forwards.local[]?
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

      local failures=0
      local stopped=0

      for tag in $(yq e '.connections[].tag' "$cfgfile"); do
        echo "----------------------------------------"
        echo "Testing connection '$tag'"
        # Pull runtime values for this connection

        local socks_port ssh_host
        socks_port=$(yq e ".connections[] | select(.tag==\"$conn_tag\").socks_proxy_port" "$cfgfile")
        ssh_host=$(yq e ".connections[] | select(.tag==\"$conn_tag\").ssh_host" "$cfgfile")

        # ---------------------------------------------------------------------
        # Ensure the SOCKS proxy for this connection is running
        # ---------------------------------------------------------------------
        if ! is_running "susops-ssh-${tag}" "SOCKS5 proxy" true "$socks_port" "SSH host: ${ssh_host:-<unset>}"; then
          stopped=$((stopped+1))
          continue
        fi

        ##################################################################
        # Run tests
        ##################################################################
        if [[ $1 == --all ]]; then
          # 1) All PAC hosts
          yq e ".connections[]
                | select(.tag==\"$conn_tag\")
                | (.pac_hosts // [])[].host" "$cfgfile" | while read -r host; do
            test_entry "$host" || failures=$((failures+1))
          done

          # 2) All local forwards (by src port)
          yq e ".connections[]
                | select(.tag==\"$conn_tag\")
                | (.forwards.local // [])[].src" "$cfgfile" | while read -r port; do
            test_entry "$port" || failures=$((failures+1))
          done

          # 3) All remote forwards (by src port on remote)
          yq e ".connections[]
                | select(.tag==\"$conn_tag\")
                | (.forwards.remote // [])[].src" "$cfgfile" | while read -r port; do
            test_entry "$port" || failures=$((failures+1))
          done
        else
          # Single target
          test_entry "$1" || failures=1
        fi

        # Return value mirrors success/failure
        [[ $failures -eq 0 ]] && return 0 || return 1
      done
      ;;

    ##############################################################################
    # add_connection <tag> [ssh_host]
    # - Creates a new empty connection block.
    # - Fails if the tag already exists or is empty/contains spaces.
    ##############################################################################
    add-conn)
      local tag=$1
      local host=${2:-""}

      [[ -z $tag || $tag =~ [[:space:]] ]] && {
        echo "Error: TAG must be non-empty and contain no whitespace"; return 1; }

      # Check if host is empty
      if [[ -z $host ]]; then
        echo "Error: SSH host is required"; return 1;
      fi

      # Abort if tag already present
      if yq e ".connections[] | select(.tag == \"$tag\")" "$cfgfile" | grep -q . >/dev/null; then
        echo "Error: connection '$tag' already exists"; return 1
      fi

      # Test ssh connection to host
      if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$host" exit 2>/dev/null; then
        echo "Error: SSH connection to '$host' failed"; return 1
      fi

      # Append new entry
      yq e -i \
        ".connections += [{\"tag\": \"$tag\", \"ssh_host\": \"$host\", \
                           \"socks_proxy_port\": 0, \
                           \"forwards\": {\"local\": [], \"remote\": []}, \
                           \"pac_hosts\": []}]" \
        "$cfgfile"

      echo "✅ added connection '$tag'${host:+ (ssh_host=$host)}"
      ;;

    ##############################################################################
    # remove_connection <tag>
    # - Stops the connection if running, then deletes its YAML block.
    ##############################################################################
    rm-conn)
      local tag=$1
      [[ -z $tag ]] && { echo "Usage: susops rm-conn TAG"; return 1; }

      # Delete from YAML
      if ! yq e ".connections[] | select(.tag == \"$tag\")" "$cfgfile" | grep -q . >/dev/null; then
        align_printf "❌ not found" "Connection [$tag]:"
        return 1
      fi

       # Stop tunnel if still running
      stop_by_name "susops-ssh-$tag" "SOCKS5 proxy [$tag]:" false "$tag"
      yq e -i "del(.connections[] | select(.tag == \"$tag\"))" "$cfgfile"
      align_printf "✅ removed" "Connection [$tag]:"
      return 0
      ;;


    help)
      cat <<EOF
Usage: susops [--conn TAG] COMMAND [ARGS]
Commands:
  start [SSH_HOST]             Start SOCKS proxy + unified PAC
  stop [--keep-ports]          Stop services
  add-local TAG SRC DST        Add a local forward
  rm-local TAG|SRC             Remove a local forward
  add-remote TAG SRC DST       Add a remote forward
  rm-remote TAG|SRC            Remove a remote forward
  add-host HOST [TAG]          Add entry to PAC
  rm-host HOST|TAG             Remove entry from PAC
  ls                           Show config for active connection
  help                         Show this help message
EOF
      ;;

    *)
      susops help; return 1
      ;;
  esac
}

# Auto-run if executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  susops "$@"
fi
