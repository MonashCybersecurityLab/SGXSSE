#ifndef SERVER_H
#define SERVER_H

#include "../common/data_type.h"
#include "Utils.h"
 
class Server{
    public:
        Server(); 
        ~Server();
        void ReceiveEncDoc(entry encrypted_doc);
        std::vector<std::string> QueryToken(rand_t* token_list, size_t token_size);
        std::vector<std::string> QueryDeletion(rand_t* token_list, size_t token_size);
        void ReceiveUpdate(rand_t* v1, rand_t* v2, size_t utoken_size, int op);
        std::string RetrieveDoc(std::string id);
        void Display_Test();

    private:
        std::unordered_map<std::string, std::string> M_I;
        std::unordered_map<std::string, std::string> M_c;
        std::unordered_map<std::string, std::string> D;
        std::unordered_map<std::string, std::string> d;
        std::unordered_map<std::string, std::string> R_Doc;
};
 
#endif
