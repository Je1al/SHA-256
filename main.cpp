#include "SHA256.hpp"
#include <iostream>
#include <fstream>
#include <chrono>

void hashString(){
    SHA256 sha;
    std::string input;
    std::cout << "Введите строки для хеширования (пустая строка для завершения):\n";
    while(true){
        std::getline(std::cin,input);
        if(input.empty()) break;
        sha.sha256_update(reinterpret_cast<const uint8_t*>(input.c_str()),input.size());
    }
    uint8_t hash[SHA256::HASH_SIZE];
    sha.sha256_final(hash);
    char hex[SHA256::HASH_SIZE*2+1];
    SHA256::hashToHex(hash,hex,sizeof(hex));
    std::cout << "SHA-256: " << hex << "\n";
}

void hashFile(){
    std::cout << "Введите имя файла: ";
    std::string filename;
    std::getline(std::cin,filename);
    std::ifstream file(filename,std::ios::binary);
    if(!file.is_open()){ std::cout<<"Ошибка открытия файла!\n"; return; }

    SHA256 sha;
    sha.sha256_init();
    uint8_t buffer[SHA256::BLOCK_SIZE];
    while(file.read(reinterpret_cast<char*>(buffer),sizeof(buffer)) || file.gcount()>0){
        sha.sha256_update(buffer,file.gcount());
    }
    uint8_t hash[SHA256::HASH_SIZE];
    sha.sha256_final(hash);
    char hex[SHA256::HASH_SIZE*2+1];
    SHA256::hashToHex(hash,hex,sizeof(hex));
    std::cout << "SHA-256 файла: " << hex << "\n";
    file.close();
}

void testHMAC(){
    std::string message,key;
    std::cout << "Введите строку: ";
    std::getline(std::cin,message);
    std::cout << "Введите ключ: ";
    std::getline(std::cin,key);
    uint8_t out[SHA256::HASH_SIZE];
    SHA256::sha256_hmac(reinterpret_cast<const uint8_t*>(key.c_str()),key.size(),
                        reinterpret_cast<const uint8_t*>(message.c_str()),message.size(),
                        out);
    char hex[SHA256::HASH_SIZE*2+1];
    SHA256::hashToHex(out,hex,sizeof(hex));
    std::cout << "HMAC-SHA256: " << hex << "\n";
}

void benchmark(){
    std::vector<uint8_t> data(10*1024*1024,0x41); // 10 MB
    SHA256 sha;
    sha.sha256_init();
    auto start = std::chrono::high_resolution_clock::now();
    sha.sha256_update(data.data(),data.size());
    uint8_t hash[SHA256::HASH_SIZE];
    sha.sha256_final(hash);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end-start;
    std::cout << "Хеширование " << data.size() << " байт заняло " << diff.count() << " секунд.\n";
}

int main(){
    while(true){
        std::cout << "\nМЕНЮ:\n";
        std::cout << "**********************************************************************\n";
        std::cout << "1. Хеширование строки (ручной ввод)\n";
        std::cout << "2. Хеширование файла\n";
        std::cout << "3. Тестирование HMAC-SHA256\n";
        std::cout << "4. Запуск стандартных тестов\n";
        std::cout << "5. Бенчмарк производительности\n";
        std::cout << "6. Инкрементальное хеширование\n";
        std::cout << "7. Выход\n";
        std::cout << "Выберите пункт: ";

        std::string choice;
        std::getline(std::cin,choice);
        if(choice=="1") hashString();
        else if(choice=="2") hashFile();
        else if(choice=="3") testHMAC();
        else if(choice=="4") { std::cout<<"Тесты не реализованы.\n"; }
        else if(choice=="5") benchmark();
        else if(choice=="6") { std::cout<<"Инкрементальное хеширование через пункт 1.\n"; hashString();}
        else if(choice=="7") break;
        else std::cout << "Неверный выбор, попробуйте снова.\n";
    }
    return 0;
}
