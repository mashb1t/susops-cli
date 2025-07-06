<p align="center">
    <img src="icon.png" alt="Menu" height="200" />
</p>

# SusOps CLI - SSH Utilities & SOCKS5 Operations

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
| Secure remote desktop            | Local Forwarding  | Tunnel RDP/VNC (`3389`) or SSH to `localhost:3389` for encrypted access to your remote workstation.          |
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
brew link susops
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

### 2. Configure Connection

```bash
so add-connection <tag> <ssh_host> <socks_proxy_port>
so start
```

## Explanation

SusOps can be used to create a **SOCKS5 proxy** and **remote port forwarder** over SSH.
It uses [autossh](https://www.harding.motd.ca/autossh/) (when installed) to automatically restart the SSH connection if it drops.

The tool is designed to be simple and effective for users needing to tunnel traffic through a remote server.:
1. **Dynamic SOCKS5 forwarding** (`ssh -N -D <socks_port>`)
2. **remote port forwarding** (`-R <remote_port>:localhost:<local_port>`)
3. **PAC file** and built-in HTTP server for serving browser proxy settings to Chrome/Firefox.

SusOps supports multiple simultaneous connections to different hosts, and you can add/remove port forwards and hosts at any time.

## SOCKS5 Proxy
### What it does

- **Creates a SOCKS5 proxy** on the SSH host.
- Allows you to tunnel traffic through the SSH server.
- Useful for bypassing firewalls, accessing geo-restricted content, or securing your browsing on public Wi-Fi.

### How to start a SOCKS5 proxy

Configure and start the proxy:
```bash
so start
so add <domain>
so restart
```

> [!NOTE]  
> You only have to set the SSH host once. Ports will be different each time you start the proxy, except you explicitly set them with e.g. `so start 1080 1081` or stop via `so stop --keep-ports`. 

Launch a browser (only once per session) to pick up the PAC file:

```bash
so chrome
# or
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

## File Sharing

SusOps includes secure file transfer commands to share and fetch files between your local machine and the remote SSH host using the established SOCKS5 connection and port forwarding:

### What it does

- **share**: Creates a temporary remote forward to serve a local file on the SSH host
- **fetch**: Uses a local forward to download a file from the SSH host

### How to share a file

```bash
# Share a local file (creates temporary remote forward)
so share /path/to/local/file.txt

# Share with custom password
so share /path/to/local/file.txt mypassword

# Share with custom password and port
so share /path/to/local/file.txt mypassword 8080
```

When sharing, SusOps:
1. Creates a temporary remote forward through the SOCKS5 tunnel
2. Compresses and encrypts the file using AES-256-CTR
3. Serves the file on the remote host at `http://localhost:<port>` with HTTP Basic authentication
4. The file becomes accessible from the SSH host using the provided password

> [!NOTE]
> File sharing only supports single files, not directories. The file is automatically compressed and encrypted before transfer.

### How to fetch a file

```bash
# Fetch a file from a share server on the SSH host
so fetch 8080 mypassword

# Fetch to a specific local destination
so fetch 8080 mypassword downloaded_file.txt
```

When fetching, SusOps:
1. Connects to the share server on the SSH host via local forwarding
2. Downloads the encrypted and compressed file using HTTP Basic authentication
3. Automatically decrypts and decompresses the file locally
4. Saves with the original filename or specified output name

> [!TIP]
> Both share and fetch operations use the active SOCKS5 connection and SSH tunneling for security. Files are automatically compressed with gzip and encrypted with AES-256-CTR during transfer.

## Under the hood

<details>
<summary>Dynamic SOCKS5 Forwarding</summary>

### How is a host selected?
The PAC file contains rules like:

```js
if (host === "example.com" || dnsDomainIs(host, ".example.com"))
    return "SOCKS5 127.0.0.1:<socks_port>";
```

This condition matches the exact domain (example.com) and all levels of subdomains (e.g., bar.foo.example.com).
Only matching (sub)domains are tunneled through the SOCKS proxy. Others use direct connections.

</details>

<details>
<summary>Local Forwarding</summary>

See https://www.ssh.com/academy/ssh/tunneling-example#local-forwarding

1. **During `so start`**
   - Reads each line in the config, builds `ssh` args:

     ```text
     -L 3000:localhost:8000
     -L 5000:localhost:8001
     ```

2. Passes them to `ssh -N -D <socks_port> …` which establishes the local port forwards on your machine.

</details>

<details>
<summary>Remote Forwarding</summary>

See https://www.ssh.com/academy/ssh/tunneling-example#remote-forwarding

1. **During `so start`**
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

## How To Use Susops As Docker Proxy

<details>
<summary>With admin permissions</summary>

Add the PAC config file URL directly as System Proxy for your network interface for automatic proxy configuration. Docker Desktop will automatically use the system proxy.

</details>

<details>
<summary>Without admin permissions</summary>

<details>
<summary>Option 1: Use PAC file directly in Docker Desktop</summary>

Prerequisites:
- Docker hub account with assigned organization and active Business subscription. Team is not sufficient, see https://www.docker.com/pricing/ (Hardened Docker Desktop)

Continue with the following commands:
1. `sudo mkdir /Library/Application\ Support/com.docker.docker`
2. `sudo vim admin-settings.json`

Add content (see https://docs.docker.com/security/for-admins/hardened-desktop/air-gapped-containers/#configuration):

```
{
  "configurationFileVersion": 2,
  "containersProxy": {
    "mode": "manual",
    "pac": "http://localhost:<your-pac-port>/proxy.pac"
  }
}
```

3. `sudo vim registry.json`

Add content (see https://docs.docker.com/security/for-admins/enforce-sign-in/methods/#registryjson-method-all, org name from dropdown on the left of https://hub.docker.com/):

```
{
  "allowedOrgs": ["<your-organizaion-name>"]
}
```

4. Quit Docker Desktop
5. Open Docker Desktop
6. Login with your docker hub account (now enforced)
7. Check by "docker exec -it <container-id> bash" (or sh), then calling curl https://<blocked-website>", add -k if necessary (ssl check disabled)

Keep in mind that Docker Desktop has to be restarted if the pac file content changes (every time you add/remove/change rules or connections)

</details>

<details>
<summary>Option 2: Use separate HTTP / HTTPS proxy in Docker Desktop</summary>

1. Add docker-compose.yml file with this content:

```
services:
  tinyproxy:
    image: ajoergensen/tinyproxy:latest
    container_name: tinyproxy
    volumes:
      - ./tinyproxy.conf:/etc/tinyproxy/tinyproxy.conf:ro
    extra_hosts:
      - host.docker.internal:host-gateway

networks:
  tinyproxy:
    external: true
```

Then choose one of the following options:
<details>
<summary>Option 1: Configure in Docker Desktop</summary>
    
1. Add port mount "8888:8888" to tinyproxy docker-compose container config
2. Set HTTP and HTTPS Web Server in Docker Desktop > Settings > Resources > Proxies > Manual proxy configuration to http://localhost:8888
3. Apply & restart

</details>

<details>
<summary>Option 2: Use Container in docker compose</summary>

1. Create the external network: docker network create tinyproxy
2. Create file tinyproxy.conf with the following content:

```
Port 8888
Listen 0.0.0.0

upstream none "."

upstream socks5 host.docker.internal:<socks5-proxy-port> "example.com"
```

SOCKS5 proxy port for the specific connection can be found in Susops > click "Status: running"

Configure the target container:

3. Add the network to the target container definition (see https://docs.docker.com/reference/compose-file/services/#networks):

```
services:
  app:
    networks:
      - tinyproxy

networks:
  tinyproxy:
    external: true
```

4. Add the following env vars to each container you’d like to use the proxied domains in:

```
- HTTP_PROXY=http://tinyproxy:8888
- HTTPS_PROXY=http://tinyproxy:8888
- NO_PROXY=localhost,127.0.0.1
```

> [!TIP]
> If you only need the proxy in one specific docker-compose.yml file you may also use the default network by not specifying one, linking by container name is sufficient then. Optional: Make your app container dependent on tinyproxy with a config like this one to follow best practice:


```
services:
  app:
    depends_on:
      tinyproxy:
        condition: service_started
```
</details>

</details>

</details>

## Troubleshooting

- **Command `susops` / `so` not found**
  - You may have installed the cask first. Run ``brew link susops`` to link the commands manually.

- **“Connection refused”** on the remote port 
  - Make sure your local service is listening on the specified `LOCAL_PORT`. 
  - Ensure the remote server’s sshd daemon config allows remote port forwarding.
    Check `/etc/ssh/sshd_config` for `AllowTcpForwarding yes` (default `yes`) and `GatewayPorts yes` or `GatewayPorts clientspecified` (default `no`).
    Further information: https://www.ssh.com/academy/ssh/tunneling-example#remote-forwarding

- **Can't start proxy**
  - If you have protected your private key with a passphrase, please create a separate key without passphrase, as SusOps can't handle interactive password input. 

- **Port in use**
  - If you see “bind: Address already in use” in SSH logs, choose a different remote port or free up the existing one with `so rm -r <port>`.

- **Tests are failing**
  - Ensure `curl` is installed and available in your PATH.
  - Check if the SSH host is reachable and the port is open.
  - Verify that the local service is running and accessible on the specified port.
  - Local and remote ports are checked for actual traffic delivery with `HTTP`, SOCKS5 forwarding with `HTTPS`. If you want to use any other protocol, you can test them with e.g. `netstat` or `nc` (netcat).

## License

MIT © 2025 Manuel Schmid — see [LICENSE](LICENSE).
