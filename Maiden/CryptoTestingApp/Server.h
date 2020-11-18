#ifndef SERVER_H
#define SERVER_H

#include "../common/data_type.h"
#include "Utils.h"

class Server{
    public:
        Server(); 
        ~Server();
        void ReceiveEncDoc(entry *encrypted_doc);
        void ReceiveTransactions(rand_t *t1_u_arr,rand_t *t1_v_arr,
                                 int pair_count);
        std::string Retrieve_Encrypted_Doc(std::string del_id_str);

        
        void Del_Encrypted_Doc(std::string del_id_str);

        void Display_Repo();
        void Display_M_I();

        std::vector<std::string> retrieve_query_results(
								rand_t *Q_w_u_arr,rand_t *Q_w_id_arr,
								int pair_count);

        
    private:
        std::unordered_map<std::string,std::string> M_I;
        std::unordered_map<std::string,std::string> R_Doc;
};
 
#endif
