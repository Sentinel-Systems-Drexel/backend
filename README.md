# Sentinel API

Analyzes emails using open source tools and free-to-use third-party APIs.

Notable inegrations include...
- Rspamd - [view docs](https://docs.rspamd.com/)
- ClamAV - [view docs](https://docs.clamav.net/)
- IP-api - [visit](https://ip-api.com/)
- Mapbox - [visit](https://www.mapbox.com/)

## Hardware Reccomendations

- 4 Cores CPU
- 8GB Memory
- 32GB Disk
- Stable 50mbps+ network connection

## Installation

We've made running your own instance of our API as simple as possible. Just follow the steps below.

1. Install docker on the same host you will be running the API. Here are some reccomended installation guides.
    - Ubuntu - [Digital Ocean](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-22-04)
2. Clone this repository.
```
git clone https://github.com/Sentinel-Systems-Drexel/backend.git
```
4. ADD SETUP INSTRUCTIONS FOR API KEYS HERE
3. Start the cluster.
```
sudo docker compose up -d --build
```
4. The api should now be reachable at ```http://<local_address>:8000```. E.g. ```http://127.0.0.1:8000```, ```http://localhost:8000```, ```http://192.168.1.26:8000```.

## Persistent Email Analysis Storage

Email analysis files are stored in a host-mounted directory so they persist across container restarts and rebuilds.

- Host path: `./email-analysis-data`
- Container path: `/data/email-analysis`

The API writes outputs to the directory set by `EMAIL_ANALYSIS_DIR` (default: `/data/email-analysis`).