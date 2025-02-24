#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t; // Define socklen_t for Windows
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <iostream>
#include <string>
#include <thread>

#define PORT 8080
#define BUFFER_SIZE 1024
#define SHIFT 3

// Initialize Winsock on Windows
void initializeWinsock() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed! Error: " << WSAGetLastError() << std::endl;
        exit(1);
    }
#endif
}

// Clean up Winsock on Windows
void cleanupWinsock() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Caesar cipher for encryption/decryption
std::string caesarCipher(const std::string& input, int shift) {
    std::string output = input;
    for (char& c : output) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            c = (c - base + shift + 26) % 26 + base;
        }
    }
    return output;
}

void receiveMessages(int sockfd, sockaddr_in clientAddr) {
    char buffer[BUFFER_SIZE];
    socklen_t addrLen = sizeof(clientAddr);

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytesReceived = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&clientAddr, &addrLen);
        if (bytesReceived < 0) {
#ifdef _WIN32
            std::cerr << "Error receiving message: " << WSAGetLastError() << std::endl;
#else
            perror("Error receiving message");
#endif
            break;
        }

        std::string decryptedMessage = caesarCipher(std::string(buffer, bytesReceived), -SHIFT);
        std::cout << "Received: " << decryptedMessage << std::endl;
    }
}

void sendMessages(int sockfd, sockaddr_in clientAddr) {
    std::string message;
    socklen_t addrLen = sizeof(clientAddr);

    // Prompt for the target IP address
    std::string targetIp;
    std::cout << "Enter the IP address of the recipient: ";
    std::getline(std::cin, targetIp);

    // Convert IP address to binary form
    if (inet_pton(AF_INET, targetIp.c_str(), &clientAddr.sin_addr) <= 0) {
        std::cerr << "Invalid IP address format." << std::endl;
        return;
    }

    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(PORT);

    std::cout << "Sending messages to " << targetIp << " on port " << PORT << "..." << std::endl;

    while (true) {
        std::getline(std::cin, message);

        std::string encryptedMessage = caesarCipher(message, SHIFT);
        int bytesSent = sendto(sockfd, encryptedMessage.c_str(), encryptedMessage.size(), 0,
                               (struct sockaddr*)&clientAddr, addrLen);

        if (bytesSent < 0) {
#ifdef _WIN32
            std::cerr << "Error sending message: " << WSAGetLastError() << std::endl;
#else
            perror("Error sending message");
#endif
        } else {
            std::cout << "Sent: " << encryptedMessage << " (" << bytesSent << " bytes)" << std::endl;
        }
    }
}



int main() {
    initializeWinsock();

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
#ifdef _WIN32
        std::cerr << "Socket creation failed! Error: " << WSAGetLastError() << std::endl;
#else
        perror("Socket creation failed");
#endif
        cleanupWinsock();
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
#ifdef _WIN32
        std::cerr << "Bind failed! Error: " << WSAGetLastError() << std::endl;
#else
        perror("Bind failed");
#endif
        cleanupWinsock();
        return 1;
    }

    std::cout << "Server is listening on port " << PORT << "..." << std::endl;

    sockaddr_in clientAddr{};

    std::thread receiverThread(receiveMessages, sockfd, clientAddr);
    std::thread senderThread(sendMessages, sockfd, clientAddr);

    receiverThread.join();
    senderThread.join();

#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    cleanupWinsock();
    return 0;
}
