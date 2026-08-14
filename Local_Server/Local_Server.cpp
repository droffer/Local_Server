#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>
#include <sstream>
#include <functional>
#include <vector>
#include <fstream>
#include <random>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 4096;

// ============================================================================
// 1. THREAD POOL (Пул рабочих потоков)
// ============================================================================

class ThreadPool {
public:
    ThreadPool(size_t threadsCount) : m_stop(false) {
        for (size_t i = 0; i < threadsCount; ++i) {
            m_workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->m_queueMutex);
                        this->m_cv.wait(lock, [this] {
                            return this->m_stop || !this->m_tasks.empty();
                            });

                        if (this->m_stop && this->m_tasks.empty()) return;

                        task = std::move(this->m_tasks.front());
                        this->m_tasks.pop();
                    }
                    task();
                }
                });
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_tasks.push(task);
        }
        m_cv.notify_one();
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_stop = true;
        }
        m_cv.notify_all();
        for (std::thread& worker : m_workers) {
            if (worker.joinable()) worker.join();
        }
    }

private:
    std::vector<std::thread> m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex m_queueMutex;
    std::condition_variable m_cv;
    bool m_stop;
};

// ============================================================================
// 2. ХРАНИЛИЩЕ ПОЛЬЗОВАТЕЛЕЙ (Потокобезопасная БД)
// ============================================================================

enum class RegisterResult {
    Success,
    AlreadyExists,
    InvalidCharacters,
    EmptyFields
};

enum class LoginResult {
    Success,
    UserNotFound,
    WrongPassword,
    EmptyFields
};

class UserDatabase {
public:
    static UserDatabase& getInstance() {
        static UserDatabase instance;
        return instance;
    }

    bool isValidUsername(std::string_view username) const {
        if (username.empty()) return false;

        for (char c : username) {
            bool isEnglishLetter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            bool isDigit = (c >= '0' && c <= '9');
            bool isUnderscore = (c == '_');

            if (!isEnglishLetter && !isDigit && !isUnderscore) {
                return false;
            }
        }
        return true;
    }

    std::string hashPassword(std::string_view password, std::string_view salt) const {
        std::string saltedPassword = std::string(password) + std::string(salt);
        size_t hash = 14695981039346656037ULL;
        for (char c : saltedPassword) {
            hash ^= static_cast<size_t>(c);
            hash *= 1099511628211ULL;
        }
        return std::to_string(hash);
    }

    std::string generateSalt(size_t length = 8) const {
        const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

        std::string salt;
        for (size_t i = 0; i < length; ++i) {
            salt += charset[dist(rng)];
        }
        return salt;
    }

    RegisterResult registerUser(const std::string& username, const std::string& password) {
        if (username.empty() || password.empty()) {
            return RegisterResult::EmptyFields;
        }

        if (!isValidUsername(username)) {
            return RegisterResult::InvalidCharacters;
        }

        std::lock_guard<std::mutex> lock(m_dbMutex);

        if (m_users.find(username) != m_users.end()) {
            return RegisterResult::AlreadyExists;
        }

        std::string salt = generateSalt();
        std::string hashedPassword = hashPassword(password, salt);

        m_users[username] = { username, hashedPassword, salt };

        std::ofstream dbFile("users_db.txt", std::ios::app);
        if (dbFile.is_open()) {
            dbFile << username << ":" << salt << ":" << hashedPassword << "\n";
        }

        return RegisterResult::Success;
    }

    LoginResult loginUser(const std::string& username, const std::string& password) {
        if (username.empty() || password.empty()) {
            return LoginResult::EmptyFields;
        }

        std::lock_guard<std::mutex> lock(m_dbMutex);

        auto it = m_users.find(username);
        if (it == m_users.end()) {
            return LoginResult::UserNotFound;
        }

        const User& user = it->second;
        std::string inputPasswordHash = hashPassword(password, user.salt);

        if (inputPasswordHash != user.passwordHash) {
            return LoginResult::WrongPassword;
        }

        return LoginResult::Success;
    }

private:
    struct User {
        std::string username;
        std::string passwordHash;
        std::string salt;
    };

    UserDatabase() {
        loadFromDisk();
    }

    void loadFromDisk() {
        std::ifstream dbFile("users_db.txt");
        if (!dbFile.is_open()) return;

        std::string line;
        size_t count = 0;
        while (std::getline(dbFile, line)) {
            if (line.empty()) continue;

            std::stringstream ss(line);
            std::string username, salt, hash;

            if (std::getline(ss, username, ':') &&
                std::getline(ss, salt, ':') &&
                std::getline(ss, hash, ':')) {
                m_users[username] = { username, hash, salt };
                count++;
            }
        }
        std::cout << " [DB] Успешно загружено пользователей из текстовой БД: " << count << "\n";
    }

    std::unordered_map<std::string, User> m_users;
    std::mutex m_dbMutex;
};

// ============================================================================
// 3. HTTP СТРУКТУРЫ (Запрос и Ответ)
// ============================================================================

struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    // Информация об IP и порте клиента
    std::string clientIp;
    uint16_t clientPort = 0;

    std::unordered_map<std::string, std::string> parseFormData() const {
        std::unordered_map<std::string, std::string> result;
        std::string_view view(body);

        size_t start = 0;
        while (start < view.size()) {
            size_t eqPos = view.find('=', start);
            if (eqPos == std::string_view::npos) break;

            size_t ampPos = view.find('&', eqPos);
            if (ampPos == std::string_view::npos) ampPos = view.size();

            std::string key(view.substr(start, eqPos - start));
            std::string val(view.substr(eqPos + 1, ampPos - eqPos - 1));

            result[key] = val;
            start = ampPos + 1;
        }
        return result;
    }

    // Вспомогательный метод для получения заголовка без учета регистра
    std::string getHeader(const std::string& name) const {
        for (const auto& [key, value] : headers) {
            if (_stricmp(key.c_str(), name.c_str()) == 0) {
                return value;
            }
        }
        return "Unknown";
    }
};

struct HttpResponse {
    int statusCode = 200;
    std::string statusText = "OK";
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    std::string toString() const {
        std::string response = "HTTP/1.1 " + std::to_string(statusCode) + " " + statusText + "\r\n";

        auto headersCopy = headers;
        if (headersCopy.find("Content-Length") == headersCopy.end()) {
            headersCopy["Content-Length"] = std::to_string(body.size());
        }
        if (headersCopy.find("Content-Type") == headersCopy.end()) {
            headersCopy["Content-Type"] = "text/html; charset=utf-8";
        }
        headersCopy["Connection"] = "close";

        for (const auto& [key, value] : headersCopy) {
            response += key + ": " + value + "\r\n";
        }
        response += "\r\n" + body;
        return response;
    }
};

// ============================================================================
// 4. HTTP ПАРСЕР
// ============================================================================

class HttpParser {
public:
    static std::optional<HttpRequest> parse(std::string_view rawRequest, const std::string& clientIp, uint16_t clientPort) {
        if (rawRequest.empty()) return std::nullopt;

        HttpRequest request;
        request.clientIp = clientIp;
        request.clientPort = clientPort;

        size_t lineEnd = rawRequest.find("\r\n");
        if (lineEnd == std::string_view::npos) return std::nullopt;

        std::string_view startLine = rawRequest.substr(0, lineEnd);

        size_t firstSpace = startLine.find(' ');
        size_t secondSpace = startLine.find(' ', firstSpace + 1);

        if (firstSpace == std::string_view::npos || secondSpace == std::string_view::npos) {
            return std::nullopt;
        }

        request.method = std::string(startLine.substr(0, firstSpace));
        request.path = std::string(startLine.substr(firstSpace + 1, secondSpace - firstSpace - 1));
        request.version = std::string(startLine.substr(secondSpace + 1));

        size_t currentPos = lineEnd + 2;
        while (currentPos < rawRequest.size()) {
            size_t nextLineEnd = rawRequest.find("\r\n", currentPos);
            if (nextLineEnd == std::string_view::npos) break;

            std::string_view line = rawRequest.substr(currentPos, nextLineEnd - currentPos);
            currentPos = nextLineEnd + 2;

            if (line.empty()) {
                request.body = std::string(rawRequest.substr(currentPos));
                break;
            }

            size_t colonPos = line.find(':');
            if (colonPos != std::string_view::npos) {
                std::string key(line.substr(0, colonPos));
                std::string_view valView = line.substr(colonPos + 1);

                while (!valView.empty() && valView.front() == ' ') {
                    valView.remove_prefix(1);
                }
                request.headers[key] = std::string(valView);
            }
        }

        return request;
    }
};

// ============================================================================
// 5. ШАБЛОННЫЙ TCP СЕРВЕР С THREAD POOL
// ============================================================================

template <typename RequestHandler>
class TcpServer {
public:
    TcpServer(int port, RequestHandler handler)
        : m_port(port), m_handler(std::move(handler)), m_serverSocket(INVALID_SOCKET) {
    }

    ~TcpServer() { stop(); }

    bool start() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

        m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_serverSocket == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(m_port);

        if (bind(m_serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(m_serverSocket);
            WSACleanup();
            return false;
        }

        if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(m_serverSocket);
            WSACleanup();
            return false;
        }

        std::cout << "===========================================\n";
        std::cout << " Server started on http://localhost:" << m_port << "\n";
        std::cout << "===========================================\n";

        runLoop();
        return true;
    }

    void stop() {
        if (m_serverSocket != INVALID_SOCKET) {
            closesocket(m_serverSocket);
            m_serverSocket = INVALID_SOCKET;
            WSACleanup();
        }
    }

private:
    void handleClient(SOCKET clientSocket, const std::string& clientIp, uint16_t clientPort) {
        char buffer[BUFFER_SIZE] = { 0 };
        int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);

        if (bytesReceived > 0) {
            std::string_view rawData(buffer, bytesReceived);
            auto parsedRequest = HttpParser::parse(rawData, clientIp, clientPort);

            HttpResponse response;
            if (parsedRequest.has_value()) {
                response = m_handler(parsedRequest.value());
            }
            else {
                response.statusCode = 400;
                response.body = "<h1>400 Bad Request</h1>";
            }

            std::string rawResponse = response.toString();
            send(clientSocket, rawResponse.c_str(), static_cast<int>(rawResponse.size()), 0);
        }

        closesocket(clientSocket);
    }

    void runLoop() {
        unsigned int threadsCount = std::thread::hardware_concurrency();
        if (threadsCount == 0) threadsCount = 4;

        ThreadPool pool(threadsCount);
        std::cout << " [INFO] ThreadPool запущен на " << threadsCount << " рабочих потоках!\n\n";

        while (true) {
            sockaddr_in clientAddr{};
            int clientAddrSize = sizeof(clientAddr);

            SOCKET clientSocket = accept(m_serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrSize);
            if (clientSocket == INVALID_SOCKET) continue;

            // Преобразуем IP адрес из сетевого формата в строку
            char ipStr[INET_ADDRSTRLEN] = { 0 };
            inet_ntop(AF_INET, &(clientAddr.sin_addr), ipStr, INET_ADDRSTRLEN);
            std::string clientIp(ipStr);
            uint16_t clientPort = ntohs(clientAddr.sin_port);

            pool.enqueue([this, clientSocket, clientIp, clientPort]() {
                this->handleClient(clientSocket, clientIp, clientPort);
                });
        }
    }

    int m_port;
    SOCKET m_serverSocket;
    RequestHandler m_handler;
};

// ============================================================================
// 6. HTML ШАБЛОНЫ
// ============================================================================

const std::string HTML_REGISTER_PAGE = R"(
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Регистрация</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 300px; }
        h2 { text-align: center; color: #333; margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #28a745; border: none; color: white; font-size: 16px; border-radius: 5px; cursor: pointer; margin-top: 10px; }
        button:hover { background: #218838; }
        .link { text-align: center; margin-top: 15px; display: block; color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Регистрация</h2>
        <form action="/register" method="POST">
            <label>Логин (English):</label>
            <input type="text" name="username" required placeholder="User_123">
            <label>Пароль:</label>
            <input type="password" name="password" required placeholder="••••••••">
            <button type="submit">Зарегистрироваться</button>
        </form>
        <a class="link" href="/login">Уже есть аккаунт? Войти</a>
    </div>
</body>
</html>
)";

const std::string HTML_LOGIN_PAGE = R"(
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Вход в систему</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 300px; }
        h2 { text-align: center; color: #333; margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; border: none; color: white; font-size: 16px; border-radius: 5px; cursor: pointer; margin-top: 10px; }
        button:hover { background: #0056b3; }
        .link { text-align: center; margin-top: 15px; display: block; color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Вход</h2>
        <form action="/login" method="POST">
            <label>Логин:</label>
            <input type="text" name="username" required placeholder="Введите ваш логин">
            <label>Пароль:</label>
            <input type="password" name="password" required placeholder="Введите пароль">
            <button type="submit">Войти</button>
        </form>
        <a class="link" href="/register">Ещё нет аккаунта? Зарегистрироваться</a>
    </div>
</body>
</html>
)";

std::string HTML_WELCOME_PAGE(const std::string& username) {
    return R"(
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Личный кабинет</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #eef2f3; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 8px 20px rgba(0,0,0,0.12); text-align: center; width: 340px; }
        h1 { color: #2c3e50; font-size: 24px; margin-bottom: 10px; }
        p { color: #7f8c8d; margin-bottom: 20px; font-size: 15px; }
        .dog-img { width: 100%; height: 230px; object-fit: cover; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        .btn { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 14px; transition: 0.2s; }
        .btn:hover { background: #bd2130; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Привет, )" + username + R"(! 👋</h1>
        <p>Авторизация прошла успешно. Вот твой пёс для хорошего настроения:</p>
        <img class="dog-img" src="https://place.dog/400/300" alt="Весёлый пёс">
        <br>
        <a href="/" class="btn">Выйти из аккаунта</a>
    </div>
</body>
</html>
    )";
}

// ============================================================================
// 7. MAIN И ТОЧКА ВХОДА
// ============================================================================

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    auto requestHandler = [](const HttpRequest& req) -> HttpResponse {
        // Достаем User-Agent из заголовков
        std::string userAgent = req.getHeader("User-Agent");

        // Выводим красивый информативный лог
        std::cout << "[LOG] [" << req.clientIp << ":" << req.clientPort << "] "
            << "[Thread: " << std::this_thread::get_id() << "] "
            << req.method << " " << req.path << "\n"
            << "      └─ User-Agent: " << userAgent << "\n";

        HttpResponse res;

        // --- Главная страница ---
        if (req.method == "GET" && req.path == "/") {
            res.body = "<h1>C++17 Multi-threaded HTTP Server</h1>"
                "<p><a href='/register'>Регистрация</a> | <a href='/login'>Вход</a></p>";
        }
        // --- Страница регистрации (GET) ---
        else if (req.method == "GET" && req.path == "/register") {
            res.body = HTML_REGISTER_PAGE;
        }
        // --- Обработка регистрации (POST) ---
        else if (req.method == "POST" && req.path == "/register") {
            auto formData = req.parseFormData();
            std::string username = formData["username"];
            std::string password = formData["password"];

            std::cout << "  [REG] Попытка регистрации логина: " << username << "\n";

            RegisterResult status = UserDatabase::getInstance().registerUser(username, password);

            switch (status) {
            case RegisterResult::Success:
                res.body = HTML_WELCOME_PAGE(username);
                break;

            case RegisterResult::AlreadyExists:
                res.statusCode = 400;
                res.body = "<h2>Ошибка!</h2><p style='color: red;'>Логин <b>" + username + "</b> уже занят.</p><a href='/register'>Назад</a>";
                break;

            case RegisterResult::InvalidCharacters:
                res.statusCode = 400;
                res.body = "<h2>Некорректный логин!</h2><p style='color: red;'>Используйте только английские буквы, цифры и '_'.</p><a href='/register'>Назад</a>";
                break;

            case RegisterResult::EmptyFields:
                res.statusCode = 400;
                res.body = "<h2>Ошибка!</h2><p style='color: red;'>Заполните все поля!</p><a href='/register'>Назад</a>";
                break;
            }
        }
        // --- Страница входа (GET) ---
        else if (req.method == "GET" && req.path == "/login") {
            res.body = HTML_LOGIN_PAGE;
        }
        // --- Обработка входа (POST) ---
        else if (req.method == "POST" && req.path == "/login") {
            auto formData = req.parseFormData();
            std::string username = formData["username"];
            std::string password = formData["password"];

            std::cout << "  [LOGIN] Попытка входа пользователя: " << username << "\n";

            LoginResult status = UserDatabase::getInstance().loginUser(username, password);

            switch (status) {
            case LoginResult::Success:
                res.body = HTML_WELCOME_PAGE(username);
                break;

            case LoginResult::UserNotFound:
                res.statusCode = 404;
                res.body = "<h2>Ошибка входа!</h2><p style='color: red;'>Пользователь <b>" + username + "</b> не найден.</p><a href='/login'>Попробовать снова</a>";
                break;

            case LoginResult::WrongPassword:
                res.statusCode = 401;
                res.body = "<h2>Ошибка входа!</h2><p style='color: red;'>Неверный пароль!</p><a href='/login'>Попробовать снова</a>";
                break;

            case LoginResult::EmptyFields:
                res.statusCode = 400;
                res.body = "<h2>Ошибка!</h2><p style='color: red;'>Заполните все поля!</p><a href='/login'>Назад</a>";
                break;
            }
        }
        // --- 404 Not Found ---
        else {
            res.statusCode = 404;
            res.statusText = "Not Found";
            res.body = "<h1>404 Page Not Found</h1>";
        }

        return res;
        };

    TcpServer server(PORT, requestHandler);
    server.start();

    return 0;
}