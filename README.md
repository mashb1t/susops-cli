# SusOps (aka. so) - Simple SSH Proxy Operations
(a little sus from the perspective of a SecOps team)


SusOps (aliased `so`) is a simple command-line tool wrapper function for managing SSH tunnels and proxy settings.
It allows you to create a SOCKS5 proxy and remote port forwarder over SSH, making it easy to tunnel traffic through a remote server.

<img src="images/so.jpg" width="500">

## Use Cases

| Scenario                         | How susops helps                                                                                            |
|----------------------------------|-------------------------------------------------------------------------------------------------------------|
| Bypass web filters               | Route only selected domains through SSH; rest of your browsing remains local.                               |
| Circumvent hotel networks        | SSH on 22/443, then use any TCP port (DB shells, RDP, Git) inside the SOCKS tunnel.                         |
| Secure browsing on hostile Wi‑Fi | Funnel chosen domains through your VPS, encrypting sensitive traffic end‑to‑end.                            |
| Geo‑testing APIs                 | Map `api.example.com` to a server in another region via reverse tunnel—no full VPN required.                |
| Remote IoT / NAS management      | Expose your local device’s UI at `remote_host:<port>` without opening extra firewall holes.                 |
| Isolated “research tab”          | Launch a browser profile through `so chrome`; keeps cookies and DNS separate from main profile.             |
| Reverse proxying to localhost    | Make ports of local services in development available for a reverse proxy on the remote server (proxy pass) |

## Setup

Download the susops repository:

```bash
git clone https://github.com/mashb1t/susops.git
cd susops
```

Source in your shell (add to ~/.bashrc, ~/.zshrc, etc.):

```bash
 echo "source ${PWD}/susops" >> ~/.zshrc
 echo 'export SUSOPS_SSH_HOST=pi # configure host in ~/.ssh/config' >> ~/.zshrc
 echo 'alias so="susops"' >> ~/.zshrc
```

Reload your shell and test it:
```bash
source ~/.bashrc   # or source ~/.zshrc
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

## Remote Port Forwarding

### What it does
- **Exposes a local service** (e.g. `localhost:3000`) on the remote SSH server’s interface.
- Makes your local app reachable at `remote_host:<remote_port>` without opening firewall holes.
- Useful for accessing local services from remote locations, e.g. as target in a reverse proxy on the remote server.

### How to register a remote forward
```bash
# Map remote port 8000 → your local port 3000
so radd 8000 3000
so restart
so test 8000
```
Now, on the SSH host (or any client that can reach it), `curl http://localhost:8000` will hit your local server on port 3000.

### How to remove it
```bash
so rrm 8000
so restart
```

### Under the hood

<details>
<summary>Dynamic SOCKS5 Forwarding</summary>

### How is a host selected?
The PAC file contains rules like:

```js
if (host === "example.com" || dnsDomainIs(host, ".example.com"))
    return "SOCKS5 127.0.0.1:<socks_port>";
```

Only matching domains go through the SOCKS proxy; others use direct connections.

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

3. **Collision Prevention**

   `so radd` refuses to add a remote port that’s already registered.

</details>

### Troubleshooting
- **“Connection refused”** on the remote port
  – Make sure your local service is listening on the specified `LOCAL_PORT`.
  – Ensure the remote server’s sshd daemon config allows remote port forwarding.
  Check `/etc/ssh/sshd_config` for `AllowTcpForwarding yes` (default `yes`) and `GatewayPorts yes` or `GatewayPorts clientspecified` (default `no`).
  Further information: https://www.ssh.com/academy/ssh/tunneling-example#remote-forwarding

- **Port in use**
  – If you see “bind: Address already in use” in SSH logs, choose a different remote port or free up the existing one with `so rrm <port>`.


## What is forwarded?

- ✅ **TCP traffic**: Any TCP socket opened by a SOCKS‑aware client is forwarded through the tunnel.
- ✅ **DNS**: Domains in the PAC file are resolved on the SSH host.
- ✅ **Ports**: Any port on the SSH host can be used for remote forwarding.

## What is not forwarded?

- ❌ **UDP traffic**: Only TCP is supported by default.
- ❌ **Non‑SOCKS clients**: Apps not configured for the proxy go direct.
