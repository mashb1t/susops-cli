# SusOps (aka. so) - Simple SSH Proxy Operations
(a little sus from the perspective of a SecOps team)

SusOps (aliased `so`) is a simple command-line tool wrapper function for managing SSH tunnels and proxy settings.
It allows you to create a SOCKS5 proxy and forward ports over SSH, making it easy to tunnel traffic using a remote server.

## Use Cases

| Scenario                         | Feature           | How SusOps helps                                                                                             |
|----------------------------------|-------------------|--------------------------------------------------------------------------------------------------------------|
| Bypass web filters               | SOCKS5 Proxy      | Route only selected domains through SSH; rest of your browsing remains local.                                |
| Circumvent hotel networks        | SOCKS5 Proxy      | SSH on 22/443, then use any TCP port (DB shells, RDP, Git) inside the SOCKS tunnel.                          |
| Secure browsing on hostile Wi‑Fi | SOCKS5 Proxy      | Funnel chosen domains through your VPS, encrypting sensitive traffic end‑to‑end.                             |
| Isolated “research tab”          | SOCKS5 Proxy      | Launch a browser profile through `so chrome`; keeps cookies and DNS separate from main profile.              |
| Access remote database           | Local Forwarding  | Forward a remote database port (e.g. MySQL `3306`) to `localhost:3306` for local querying and tooling.       |
| Develop against remote services  | Local Forwarding  | Map a remote web service port (e.g. `:8080`) to your machine so you can use local debuggers and live-reload. |
| Secure remote desktop          | Local Forwarding  | Tunnel RDP/VNC (`3389`) or SSH to `localhost:3389` for encrypted access to your remote workstation.          |
| Geo‑testing APIs                 | Remote Forwarding | Map `api.example.com` to a server in another region via reverse tunnel—no full VPN required.                 |
| Remote IoT / NAS management      | Remote Forwarding | Expose your local device’s UI at `remote_host:<port>` without opening extra firewall holes.                  |
| Reverse proxying to localhost    | Remote Forwarding | Make ports of local services in development available for a reverse proxy on the remote server (proxy pass). |
| Share local dev server           | Remote Forwarding | Expose your local development site (e.g. `localhost:3000`) on `remote_host:3000` for others to access.       |
| Receive external webhooks        | Remote Forwarding | Open a public endpoint on your SSH host for testing services like N8n or GitHub webhooks without deploying.  |

## What can be forwarded?

- ✅ **TCP traffic**: Any TCP socket opened by a SOCKS‑aware client is forwarded through the tunnel.
- ✅ **DNS**: Domains in the PAC file are resolved on the SSH host.
- ✅ **Ports**: Any port on localhost and the SSH host can be used for forwarding (both ways).

## What can not be forwarded?

- ❌ **UDP traffic**: Only TCP is supported by default.

## Setup

### 1. Install via Homebrew

```bash
brew tap mashb1t/susops
brew install susops
```

For updating, simply run these commands:

```bash
brew update
brew upgrade susops
```

### OR Install manually

Download the susops repository:

```bash
git clone https://github.com/mashb1t/susops-cli.git
cd susops
```

Source in your shell (add to ~/.zshrc, ~/.bashrc, etc.):

```bash
 echo "source ${PWD}/susops.sh" >> ~/.zshrc
 echo 'alias so="susops"' >> ~/.zshrc
```

Reload your shell and test it:
```bash
source ~/.zshrc   # or source ~/.bashrc
so --help
```

> [!TIP]
> You can configure the ssh host using the ssh config file (usually `~/.ssh/config`) to also set up proxy jumps and multi-hop SSH connections.

## Explanation

`so` can be used to create a **SOCKS5 proxy** and **remote port forwarder** over SSH.

It’s designed to be simple and effective for developers needing to tunnel traffic through a remote server.:
1. **Dynamic SOCKS5 forwarding** (`ssh -N -D <socks_port>`)
2. **remote port forwarding** (`-R <remote_port>:localhost:<local_port>`)
3. **PAC file** and built-in HTTP server for serving browser proxy settings to Chrome/Firefox.

## SOCKS5 Proxy
### What it does

- **Creates a SOCKS5 proxy** on the SSH host.
- Allows you to tunnel traffic through the SSH server.
- Useful for bypassing firewalls, accessing geo-restricted content, or securing your browsing on public Wi-Fi.

### How to start a SOCKS5 proxy

Configure and start the proxy:
```bash
so start <ssh_host>
so add <domain>
so restart
```

> [!NOTE]  
> You only have to set the SSH host once. Ports will be different each time you start the proxy, except you explicitly set them with e.g. `so start 1080 1081` or stop via `so stop --keep-ports`. 

Launch a browser (only once per session) to pick up the PAC file:

```bash
so chrome          # or
so firefox
```

> [!IMPORTANT]
> Modifying the PAC config will not immediately update an already-open browser. After adding or removing hosts, run:
> ```bash
> so chrome-proxy-settings
> ```
> and click **Re-apply settings**.

## Local Port Forwarding

### What it does
- **Forwards a remote port** (e.g. `remote_host:8000`) to a local port on your machine.
- Makes the remote app reachable at `localhost:<local_port>` without configuring remote firewall rules.
- Useful for developing against or inspecting remote services as if they were running locally.

### How to register a local forward
```bash
# Map your local port 3000 → remote_host:8000
so add -l 3000 8000
so restart
so test 3000
```

Now, on your local machine, `curl http://localhost:3000` will hit the remote server on port 8000.

### How to remove it
```bash
so rm -l 3000
so restart
```

## Remote Port Forwarding

### What it does
- **Forwards a local port** (e.g. `localhost:3000`) on the remote SSH server.
- Makes your local app reachable at `remote_host:<remote_port>` without opening firewall holes.
- Useful for accessing local services from remote locations, e.g. as target in a reverse proxy on the remote server.

### How to register a remote forward
```bash
# Map remote port 8000 → your local port 3000
so add -r 8000 3000
so restart
so test 8000
```
Now, on the SSH host (or any client that can reach it), `curl http://localhost:8000` will hit your local server on port 3000.

### How to remove it
```bash
so rm -r 8000
so restart
```

## Under the hood

<details>
<summary>Dynamic SOCKS5 Forwarding</summary>

### How is a host selected?
The PAC file contains rules like:

```js
if (host === "example.com" || dnsDomainIs(host, ".example.com"))
    return "SOCKS5 127.0.0.1:<socks_port>";
```

This condition matches the exact domain (example.com) and one level of subdomains (e.g., sub.example.com).
It does not include two or more levels of subdomains (e.g., sub.sub.example.com).
If you want to include those, you can add another rule.

Only matching (sub)domains go through the SOCKS proxy; others use direct connections.

</details>

<details>
<summary>Local Forwarding</summary>

See https://www.ssh.com/academy/ssh/tunneling-example#local-forwarding

1. **Configuration**  
   Entries are stored in `~/.susops/forward.conf` as lines:

   ```text
   <local_port> <remote_host>
    ```
2. **During `so start`**
   - Reads each line, builds `ssh` args:

     ```text
     -L 3000:localhost:8000
     -L 5000:localhost:8001
     ```

3. Passes them to `ssh -N -D <socks_port> …` which establishes the local port forwards on your machine.

</details>

<details>
<summary>Remote Forwarding</summary>

See https://www.ssh.com/academy/ssh/tunneling-example#remote-forwarding

1. **Configuration**
   Entries are stored in `~/.susops/reverse.conf` as lines:
   ```text
   <remote_port> <local_port>
   ```

2. **During `so start`**
    - Reads each line, builds `ssh` args:

      ```text
      -R 8000:localhost:3000
      -R 8001:localhost:5000
      ```

    - Passes them to `ssh -N -D <socks_port> …` which maintains the tunnels.

</details>

<details>
<summary>Port Collision Prevention</summary>

When adding a new local or remote forward, `so` checks for port collisions to prevent conflicts with existing forwards.

| Check | Local Forwarding (`so add -l LOCAL_PORT REMOTE_PORT`)                | Remote Forwarding (`so add -r REMOTE_PORT LOCAL_PORT`)                 |
|-------|----------------------------------------------------------------------|------------------------------------------------------------------------|
| 1     | Exact rule must not already exist in `~/.susops/forward.conf`        | Exact rule must not already exist in `~/.susops/reverse.conf`          |
| 2     | `LOCAL_PORT` must not already be the source of another local forward | `REMOTE_PORT` must not already be the source of another remote forward |
| 3     | `LOCAL_PORT` must not be targeted by any existing remote forward     | `REMOTE_PORT` must not be targeted by any existing local forward       |
| 4     | `REMOTE_PORT` must not already be the source of any remote forward   | `LOCAL_PORT` must not already be the source of any local forward       |

</details>

### Troubleshooting
- **“Connection refused”** on the remote port
  – Make sure your local service is listening on the specified `LOCAL_PORT`.
  – Ensure the remote server’s sshd daemon config allows remote port forwarding.
  Check `/etc/ssh/sshd_config` for `AllowTcpForwarding yes` (default `yes`) and `GatewayPorts yes` or `GatewayPorts clientspecified` (default `no`).
  Further information: https://www.ssh.com/academy/ssh/tunneling-example#remote-forwarding

- **Port in use**
  – If you see “bind: Address already in use” in SSH logs, choose a different remote port or free up the existing one with `so rrm <port>`.

- **Tests are failing**
  – Ensure `curl` is installed and available in your PATH.
  – Check if the SSH host is reachable and the port is open.
  – Verify that the local service is running and accessible on the specified port.
  - Local and remote ports are checked for actual traffic delivery with `HTTP`, SOCKS5 forwarding with `HTTPS`. If you want to use any other protocol, you can test them with e.g. `netstat` or `nc` (netcat).

## License

MIT © 2025 Manuel Schmid — see [LICENSE](LICENSE).
