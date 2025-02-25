import socket
import scapy.all as scapy

def scan_host(host):
    """Verifica se o host está ativo enviando um pacote ICMP."""
    icmp_request = scapy.IP(dst=host)/scapy.ICMP()
    response = scapy.sr1(icmp_request, timeout=1, verbose=False)
    return response is not None

def scan_ports(host, ports):
    """Escaneia as portas especificadas no host."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def main():
    target = input("Digite o endereço IP ou domínio do alvo: ")
    ports = [21, 22, 23, 25, 53, 67, 80, 110, 123, 135, 139, 143, 179, 389, 443, 445, 500, 3389]  # Lista de portas comuns
    
    print(f"Verificando se o host {target} está ativo...")
    if scan_host(target):
        print("Host ativo! Iniciando a varredura de portas...")
        open_ports = scan_ports(target, ports)
        
        if open_ports:
            print("Portas abertas encontradas:")
            for port in open_ports:
                print(f"- Porta {port} aberta")
        else:
            print("Nenhuma porta aberta encontrada.")
    else:
        print("Host inativo ou não acessível.")

if __name__ == "__main__":
    main()
