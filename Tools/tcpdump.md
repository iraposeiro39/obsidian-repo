# Overview
Wireshark da vida, mas cli. pq é bombástico

# Comando Básico
## Listen icmp
```
sudo tcpdump icmp -i <interface>
```

## Listen de todo o tráfego de uma interface
```
sudo tcpdump -i <interface>
```

## Listen de uma porta especifica
```
sudo tcpdump port <porta> -i <interface>
```

## Listen de um IP especifico
```
sudo tcpdump host <ip> -i <interface>
```

## Ficheiros externos
### Ler
```
tcpdump -r captura.pcap
```

### Guardar
```
sudo tcpdump <options> -w <file>.pcap
```
