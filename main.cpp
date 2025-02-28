#include "sha256.h"
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

// Definiamo delle costanti
#define PORT 8080
#define BUFFER_SIZE 1024
#define SHIFT 3
#define MAX_PEERS 20

// Lista dei peers
std::string peers[MAX_PEERS]; // La lista sarà un buffer circolare
int in = 0;

boolean hashSend = false; // Segna se l'utente vuole sapere l'hash dei messaggi o no

// Ringraziamo chatgpt per questo codice
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

// Codice per la crittografia di cesare (funziona come la versione in kotlin)
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

// Funzione per generare l'hash (non so perché ho deciso di metterla in una funzione)
std::string generateSHA256(const std::string& input) {
    return sha256(input);
}

// Codice per la ricevere i messaggi
void receiveMessages(int sockfd, sockaddr_in clientAddr) {
    char buffer[BUFFER_SIZE];               // Buffer che conterrà i dati letti
    socklen_t addrLen = sizeof(clientAddr); // Lunghezza dell'indirizzo

    while (true) {
        // Reset del buffer
        memset(buffer, 0, BUFFER_SIZE);

        // Ricevimento del messaggio
        int bytesReceived = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&clientAddr, &addrLen);
        if (bytesReceived < 0) {
#ifdef _WIN32
            std::cerr << "Error receiving message: " << WSAGetLastError() << std::endl;
#else
            perror("Error receiving message");
#endif
            break;
        }

        // Prendiamo i dati ricevuti
        std::string receivedData(buffer, bytesReceived);

        // Troviamo la posizione del delimitatore
        size_t delimiterPos = receivedData.find("::");

        // Se il delimitatore non c'è diamo per scontato che il messaggio sia malformato
        if (delimiterPos == std::string::npos) {
            std::cerr << "Malformed message" << std::endl;
            continue;
        }

        // Dividiamo il messaggio e l'hash ricevuto
        std::string encryptedMessage = receivedData.substr(0, delimiterPos);
        std::string receivedHash = receivedData.substr(delimiterPos + 2);

        // Calcoliamo l'hash
        std::string computedHash = generateSHA256(encryptedMessage);

        // Controlliamo se l'hash ricevuto e quello calcolato siamo diversi
        // (Il motivo per cui abbiamo deciso di controllare utilizzare gli hash
        // dei messaggi ancora criptati piuttosto di quelli già decriptati è
        // per ottimizzare il codice, se troviamo un errore tra gli hash
        // usciamo subito dal ciclo senza decriptare il messaggio in modo da
        // non dover sprecare tempo e risorse del PC per decriptare un messaggio
        // che già sappiamo non è corretto)
        if (computedHash != receivedHash) {
            std::cerr << "Hash mismatch! Possible message corruption." << std::endl;
            std::cerr << computedHash << std::endl;
            std::cerr << receivedHash << std::endl;
            continue;
        }

        // Decriptiamo il messaggio
        std::string decryptedMessage = caesarCipher(encryptedMessage, -SHIFT);

        // Convertiamo l'IP in stringa
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ipStr, INET_ADDRSTRLEN);

        // Se il messagigo contiene con0 o con1
        if (encryptedMessage.rfind("con0", 0) == 0 || encryptedMessage.rfind("con1", 0) == 0) {
            // Mi sono dimenticato a cosa serve
            bool check = true;
            for (int i = 0; i < MAX_PEERS; i++) {
                if (peers[i] == ipStr) {
                    check = false;
                    break;
                }
            }

            // Aggiungiamo il mittente alla lista di peers e andiamo avanti nel buffer circolare
            if (check) {
                peers[in] = ipStr;
                in = (in + 1) % MAX_PEERS;
            }

            // Se il messaggio contiene "con0", mandiamo indietro un messaggio "con1"
            if (encryptedMessage.rfind("con0", 0) == 0) {
                std::string res = "con1";
                std::string hash = generateSHA256(res);

                std::string messageWithHash = res + "::" + hash;

                // Forziamo la porta ad 8080
                clientAddr.sin_port = htons(8080);

                int bytesSent = sendto(sockfd, messageWithHash.c_str(), messageWithHash.size(), 0, (struct sockaddr*)&clientAddr, addrLen);
                if (bytesSent < 0) {
#ifdef _WIN32
                    std::cerr << "Error sending message: " << WSAGetLastError() << std::endl;
#else
                    perror("Error sending message");
#endif
                }
            }
        } else {
            std::cout << "Received from " << ipStr << ": " << decryptedMessage;

            if (hashSend) {
                std::cout << " (Hash: " << receivedHash << ")" << std::endl;
            }
            std::cout << std::endl;

        }
    }
}

// Funzione per forzare l'errore
void forzaErrore(int sockfd, sockaddr_in clientAddr) {
    socklen_t addrLen = sizeof(clientAddr);

    // Messaggio appositamente corrotto
    std::string fullMessage = "test::err";

    int bytesSent = sendto(sockfd, fullMessage.c_str(), fullMessage.size(), 0,
                           (struct sockaddr*)&clientAddr, addrLen);

    if (bytesSent < 0) {
        std::cerr << "Error sending messages " << std::endl;
    }
}


void sendMessages(int sockfd, sockaddr_in clientAddr) {
    std::string message;
    socklen_t addrLen = sizeof(clientAddr);

    // Abilitiamo il broadcast
    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char *>(&broadcastEnable), sizeof(broadcastEnable)) < 0) {
        perror("Error enabling broadcast");
        return;
    }

    while (true) {
        // Chiediamo l'IP all'utente
        std::string targetIp;
        std::string ipIndex;
        std::cout << "Enter dest IP address: ";
        bool first = true;
        bool notEmpty = true;

        // Controlliamo se la lista di peers è vuota o meno
        for (int i = 0; i < MAX_PEERS; i++) {
            if (peers[i] != "") {
                first = false;
            }
        }

        // Se è vuota chiediamo all'utente di inserire l'IP manualmente
        if (first) {
            std::getline(std::cin, targetIp);
        } else {
            // In caso la lista di peers non è vuota, la diamo all'utente che poi può decidere con chi comunicare
            std::cout << std::endl;
            for (int i = 0; i < MAX_PEERS && notEmpty; i++) {
                if (peers[i] == "") notEmpty = false;
                else std::cout << i << "#: " << peers[i] << std::endl;
            }

            std::getline(std::cin, ipIndex);
            targetIp = peers[std::stoi(ipIndex)];
        }

        // Convertiamo l'IP in binario (serve per controllare che il formato dell'IP sia corretto)
        if (inet_pton(AF_INET, targetIp.c_str(), &clientAddr.sin_addr) <= 0) {
            std::cerr << "Invalid IP address format." << std::endl;
            return;
        }

        clientAddr.sin_family = AF_INET;
        clientAddr.sin_port = htons(PORT);

        std::cout << "Sending messages to " << targetIp << " on port " << PORT << "..." << std::endl;

        while (true) {
            // Prendiamo un messaggio dall'utente
            std::getline(std::cin, message);

            // Comandi:
            //
            // /cambia = cambia il destinatario attraverso la lista
            // /cerca = cerca nella LAN altri host
            // /hash = toggle per indicare se si vuole anche avere l'hash dei messaggi o meno
            // /forza = manda un messaggio con un errore di hash forzato

            if (message == "/cambia") {
                break;
            } else if (message == "/cerca") {
                std::string res = "con0";

                // Manda un messaggio in broadcast
                sockaddr_in broadcastAddr = {};
                broadcastAddr.sin_family = AF_INET;
                broadcastAddr.sin_port = htons(8080);
                inet_pton(AF_INET, "255.255.255.255", &broadcastAddr.sin_addr);

                int bytesSent = sendto(sockfd, res.c_str(), res.size(), 0, (struct sockaddr*)&broadcastAddr, addrLen);
                if (bytesSent < 0) {
#ifdef _WIN32
                    std::cerr << "Error sending broadcast: " << WSAGetLastError() << std::endl;
#else
                    perror("Error sending broadcast");
#endif
                } else {
                    std::cout << "Broadcasted 'con0' to 255.255.255.255" << std::endl;
                }
                continue;
            } else if (message == "/hash") {
                hashSend = !hashSend;

                std::cout << "Return hash to user set to: " << hashSend << std::endl;

                continue;
            } else if (message == "/forza") {
                forzaErrore(sockfd, clientAddr);
                continue;
            }

            // Cifra il messaggio e si aggiunge l'hash
            std::string encryptedMessage = caesarCipher(message, SHIFT);
            std::string hash = generateSHA256(encryptedMessage);
            std::string fullMessage = encryptedMessage + "::" + hash;

            // invio del messaggio
            int bytesSent = sendto(sockfd, fullMessage.c_str(), fullMessage.size(), 0,
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
}

int main() {
    // Inizializzazione del winsock (serve per windows)
    initializeWinsock();

    // Creiamo il socket
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

    // Impostiamo il socket
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    // Associamo il socket all'IP del nostro PC
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

    std::thread receiverThread(receiveMessages, sockfd, clientAddr);    // Thread del ricevitore di messaggi
    std::thread senderThread(sendMessages, sockfd, clientAddr);         // Thread invio del messaggi

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
