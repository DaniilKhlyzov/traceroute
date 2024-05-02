import argparse
from time import time
from typing import Optional
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
import scapy.all


# Функция для отправки пакета на указанный хост
def send_packet(host: str, port: int, ttl: int, timeout: int, protocol: str, payload: Optional[str],
                source_address: Optional[str]) -> Optional[str]:
    # Создаем IP пакет в зависимости от типа хоста (IPv4 или IPv6)
    if ':' in host:
        ip_packet = IPv6(dst=host, hlim=ttl)
    else:
        ip_packet = IP(dst=host, ttl=ttl)

    # Устанавливаем исходный IP адрес, если указан
    if source_address:
        ip_packet.src = source_address

    response = None

    # Создаем и отправляем пакет в зависимости от протокола
    if protocol == "icmp":
        icmp_packet = IP(dst=host, ttl=ttl) / ICMP()  # Создаем ICMP пакет
        if payload:
            icmp_packet /= payload.encode()  # Добавляем данные в пакет, если указаны
        response = scapy.all.sr1(icmp_packet, timeout=timeout)  # Отправляем ICMP пакет и получаем ответ
    elif protocol == "tcp":
        tcp_packet = TCP(dport=port)  # Создаем TCP пакет
        if payload:
            tcp_packet /= payload.encode()  # Добавляем данные в пакет, если указаны
        response = scapy.all.sr1(ip_packet / tcp_packet, timeout=timeout)  # Отправляем TCP пакет и получаем ответ
    elif protocol == "udp":
        udp_packet = UDP(dport=port)  # Создаем UDP пакет
        if payload:
            udp_packet /= payload.encode()  # Добавляем данные в пакет, если указаны
        response = scapy.all.sr1(ip_packet / udp_packet, timeout=timeout)  # Отправляем UDP пакет и получаем ответ

    if response is not None:
        return response.src

    return None


# Функция для выполнения трассировки маршрута
def traceroute(target: str, protocol: str, timeout: int, port: int, max_hops: int, table: bool,
               int_ip: bool, source_address: Optional[str], payload: Optional[str]):
    for ttl in range(1, max_hops + 1):
        intermediate_ip = send_packet(target, port, ttl, timeout, protocol, payload, source_address)
        # Отправляем пакет на указанный хост
        if int_ip:
            print(f"Промежуточный IP: {intermediate_ip}")

        if table:
            start_time = time()
            intermediate_ip = send_packet(target, port, ttl, timeout, protocol, source_address, payload)
            # Отправляем пакет на указанный хост повторно для измерения времени
            end_time = time()
            print(f"Хоп {ttl}: IP адрес: {intermediate_ip}, Время отклика: {end_time - start_time:.2f}ms")

        if intermediate_ip == target:
            print(f"Достигнут целевой хост: {target}")  # Если получен ответ от целевого хоста, выводим сообщение
            break

        if ttl == max_hops:
            print(
                "Достигнуто максимальное количество хопов")
            # Если достигнуто максимальное количество хопов, выводим сообщение
            break


def generate_args():
    parser = argparse.ArgumentParser(description="Python Traceroute Tool")  # Создаем парсер аргументов командной строки
    parser.add_argument("target", help="Целевой IP адрес")
    parser.add_argument("protocol", choices=["tcp", "udp", "icmp"], help="Используемый протокол")
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Таймаут в секундах")
    parser.add_argument("-p", "--port", type=int, default=80, help="Порт для TCP или UDP")
    parser.add_argument("-n", "--max-requests", type=int, default=30, help="Максимальное количество запросов")
    parser.add_argument("-v", "--autonomous-system", action="store_true",
                        help="Показывать автономную систему для каждого IP адреса")
    parser.add_argument("-m", "--max-hops",default=64, type=int,  help="Максимальное количество хопов")
    parser.add_argument("--table", action="store_true", help="Отображать таблицу маршрутизации с временем отклика")
    parser.add_argument("--int-ip", action="store_true", help="Отображать промежуточные IP адреса")
    parser.add_argument("--source-address", help="Указать исходный адрес")
    parser.add_argument("--payload", help="Указать данные для пакета")
    return parser.parse_args()


if __name__ == "__main__":
    args = generate_args()
    traceroute(args.target, args.protocol, args.timeout, args.port, args.max_hops, args.table, args.int_ip,
               args.source_address, args.payload)