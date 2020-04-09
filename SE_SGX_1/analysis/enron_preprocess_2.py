import os
import operator
import pickle
import enchant
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize
import csv

class App_Controller:
    def __init__(self):
        self.run = 1
    
    def check_valid_sentence(self, sentence):
        stopping_words_sentences = ["Message-ID:","Date:","From:","To:","Subject:","Cc:","Bcc:","X-From:","X-To:","X-cc:","X-bcc:","X-Folder:","X-Origin:","X-FileName:", 
                   "Mime-Version:","Content-Type:","charset=us","Content-Transfer-Encoding"]

        for word in stopping_words_sentences:
            if word in sentence:
                return False
        return True    

    def dump_frequency_file(self, trimed_sorted_dict_frequency, file_writer):
    
        #columnTitleRow = "keyword, frequency\n"
        #file_writer.write(columnTitleRow)
    
        for index in range(len(trimed_sorted_dict_frequency)):
            keyword = trimed_sorted_dict_frequency[index][0]
            frequency = trimed_sorted_dict_frequency[index][1]
            row = keyword + "," + str(frequency) + "\n"
            file_writer.write(row)    
        
     
    #tokenise and stem the training data setinto words
    #dump to preprocessed document with increasing id
    #and dump keywords by their frequencies with an descending order   
    
    #input: enron dataset folder
    #output : processed doc folder
    
    def training_data_parser(self, origin_dir="enron_training", process_dir = "processed_dir"):

        
        proj_dir = os.getcwd()
        dst_dir= os.path.join(proj_dir, origin_dir)
        #tokenizer = nltk.data.load('tokenizers/punkt/english.pickle')
        
        ps = PorterStemmer()

        stop_words = set(stopwords.words('english'))
        stop_words.update(['!','...','?','.',''])
        english_word = enchant.Dict("en_US")

        #build an invert index dictionary
        inverted_dict = {}

        file_counter = 1
        
        
        #then read each file in that subfoler
        for dirName, subdirList, fileList in os.walk(dst_dir):
            #mount to each subfolder first
            print("->" + str(dirName))
            
            #loop through each file in this subfolder
            for email_doc in fileList:
                #print('Stemming on the file %s' % os.path.join(dst_dir, file))
                fp = open(os.path.join(dirName, email_doc))
                data = fp.read()
                voca_list = set([])
                #tokenize sentences in this document by breaking a new line 
                #tokenizer.tokenize(data)
                sentences = data.split("\n")
                for sentence in sentences:
                    #check such that the sentences doesnot belong to email format
                    is_valid = self.check_valid_sentence(sentence)
                    if is_valid:
                        words = word_tokenize(sentence)
                        for word in words:
                            #eliminate stopping words and special characters in mail format, special symbols, and word whose len is 1
                            if (not word in stop_words) and len(word) > 1 and word.isalpha():
                                #check whether the word is an English word
                                if english_word.check((word)):
            
                                    #stem using Porter algorithm to convert it into root word
                                    stem_word= ps.stem(word)
                                    voca_list.add(str(stem_word))

                #write voca_list to file with increasing id
                voca_list = list(voca_list)
                line = ",".join(voca_list)
                with open(os.path.join(process_dir, str(file_counter)), "a+") as myfile:
                    myfile.write(line)

                #add to frequency dict 
                for word in voca_list:
                    #check whether the word exists in the inverted index
                    if word in inverted_dict:
                        inverted_dict[word].add(file_counter)
                    else:
                        inverted_dict[word]= set([int(file_counter)])  

                file_counter +=1 
        

        #output the number of keywords- which is the len of inverted_dict
        print("Total the number of keywords %i" % len(inverted_dict))

        #store into keywords and frequency
        dict_frequency = {}
        for keyword in inverted_dict:
            dict_frequency[keyword] =len(inverted_dict[keyword])

        #sorted by descending order of frequencies
        sorted_dict_frequency = sorted(dict_frequency.items(), key=operator.itemgetter(1),reverse=True)      
        
        freq_dir = "enron_frequency.csv"
        file_writer = open(os.path.join(os.getcwd(), freq_dir), "w")
        self.dump_frequency_file(sorted_dict_frequency,file_writer)
        file_writer.close()
        

if __name__ == '__main__':
    app = App_Controller()
    app.training_data_parser()