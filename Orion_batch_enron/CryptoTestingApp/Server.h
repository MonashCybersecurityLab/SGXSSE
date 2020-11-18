#ifndef SERVER_H
#define SERVER_H

#include "../common/data_type.h"
#include "Utils.h"
#include "RAMStore_data.h"

class Server{
    public:
        Server(); 
        ~Server();
        void ReceiveEncDoc(entry *encrypted_doc);
        void ReceiveTransactions(rand_t *t1_u_arr,rand_t *t1_v_arr,
                                 int pair_count);
        std::string Retrieve_Encrypted_Doc(std::string del_id_str);
        std::string Retrieve_M_c(std::string u_prime_str);
        
        void Del_Encrypted_Doc(std::string del_id_str);
        void Del_M_c_value(std::string del_u_prime);

        void Display_Repo();
        void Display_M_I();
        void Display_M_c();

        std::vector<std::string> retrieve_query_results(
								rand_t *Q_w_u_arr,rand_t *Q_w_id_arr,
								int pair_count);

        void retrieve_M_c_entries(rand_t *_u_prime, 
								  v * _v_prime,
								  int *v_size, int token_size);

        void InitData(size_t blockNum);
        BUCKET GetData(int data_structure, size_t pos);
        void PutData(int data_structure, size_t pos, BUCKET b);

        
    private:
        std::unordered_map<std::string,std::string> M_I;
        std::unordered_map<std::string,std::string> M_c;
        std::unordered_map<std::string,std::string> R_Doc;

        RAMStore *data_search;

        RAMStore *data_update;
};
 
#endif
