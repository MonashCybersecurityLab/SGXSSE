#include "Server.h"

Server::Server(){
  R_Doc.clear();
  M_I.clear();
  M_c.clear();
}

Server::~Server(){
  R_Doc.clear();
  M_I.clear();
  M_c.clear();

}

void Server::ReceiveEncDoc(entry encrypted_doc){
    
    std::string id(encrypted_doc.first.content, encrypted_doc.first.content + encrypted_doc.first.content_length);
    std::string enc_content(encrypted_doc.second.message, encrypted_doc.second.message + encrypted_doc.second.message_length);
    R_Doc.insert(std::pair<std::string, std::string>(id, enc_content));
}

std::vector<std::string> Server::QueryToken(rand_t* token_list, size_t token_size) {
	std::vector<std::string> res_list;
	for(int i = 0; i < token_size; i++) {
		std::string token_string = std::string((char *) token_list[i].content, token_list[i].content_length);
		if(D.find(token_string) != D.end()) {
			res_list.push_back(D[token_string]);
			D.erase(token_string);
		}
	}
	return res_list;
}

std::vector<std::string> Server::QueryDeletion(rand_t* token_list, size_t token_size) {
	std::vector<std::string> del_list;
	for(int i = 0; i < token_size; i++) {
		std::string token_string = std::string((char *) token_list[i].content, token_list[i].content_length);
		if(d.find(token_string) != d.end()) {
			del_list.push_back(d[token_string]);
			d.erase(token_string);
		}
	}
	return del_list;
}

void Server::ReceiveUpdate(rand_t* v1, rand_t* v2, size_t utoken_size, int op) {
	//printf("%ld entries updated\n", utoken_size);
	for(int i = 0; i < utoken_size; i++) {
		std::string token_string = std::string((char *) v1[i].content, v1[i].content_length);
		std::string value_string = std::string((char *) v2[i].content, v2[i].content_length);
		if(op == ADD) {
			D[token_string] = value_string;
		} else if(op == DEL) {
			d[token_string] = value_string;
		}

	}
}

std::string Server::RetrieveDoc(std::string id) {
	return R_Doc[id];
}

/*void Server::ReceiveTransactions(std::list<entry> T1, std::list<entry> T2){
  
  std::string key, value;
  for (auto const& cur1 : T1) {
    key = cur1.first.content;
    value = cur1.second.message;
    M_I.insert(std::pair<std::string,std::string>(key,value)) ;
  }
    
  for (auto const& cur2 : T2) {
    key = cur2.first.content;
    value = cur2.second.message;
    M_c.insert(std::pair<std::string,std::string>(key,value)) ;
  }
}*/

void Server::Display_Test(){

  for ( auto it = R_Doc.begin(); it != R_Doc.end(); ++it ) {
    printf("Cipher\n");
    //printf("%s\n", (it->first).c_str());
    print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}
