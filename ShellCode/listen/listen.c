/*
    ������ ������� ��������� ������� �� winsock.
    
    ������������ ���� 1111.
    � ���� ����� ��������������: nc 127.0.0.1 1111
    
    cl listen.c /link Ws2_32.lib

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>


typedef size_t socklen_t;

int main (unsigned int argc ,char *argv[], char *envp[]) {

SOCKET sock;
SOCKET sock2;
int recv_size;
struct sockaddr_in addr;
struct sockaddr_in addr2;
char buf[1024];
WSADATA wsaData;


    int a = sizeof(wsaData);

    // �������������� ����������
    if (WSAStartup (MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        printf ("Error init library\n");
        return 1;
        }

    // ������� ����� TCP/IP
    sock = socket (AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        printf ("Error create socket %x\n", WSAGetLastError());
        WSACleanup();
        return 1;
        }

    // ��������� ��������� � �������������� �������
    memset (&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons (1111);
    addr.sin_addr.s_addr = 0;       // ������� ����� ���������

    // ����������� ����� � �����
    if (bind (sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
        printf ("Error bind %x\n", WSAGetLastError());
        WSACleanup();
        return 1;
        }

    // ��������� ����� � ����� �������������
    if (listen (sock, 100) == SOCKET_ERROR) {
        printf ("Error listen %x\n", WSAGetLastError());
        WSACleanup();
        return 1;
        }

    // ������� �������� ���������� � �������� ����� ����������
    sock2 = accept (sock, (struct sockaddr*)&addr2, NULL);
    if (sock2 == -1) {
        printf ("error accept\n");
        WSACleanup();
        return 1;
        }

    // ��������� ������ �� ������
    recv_size = recv (sock2, buf, 1024, 0);
    buf[recv_size] = 0;
    printf ("%s\n", buf);

    // �������� ������ � �����
    //send (sock2, buf, recv_size, 0);

    WSACleanup();
    
    return 0;
}

