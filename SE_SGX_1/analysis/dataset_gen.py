import os
import operator
import csv,pickle
import random
import operator

class StreamingSet:
    def __init__(self,nocount):

        self.choice = nocount

        self.freq = dict()

    #function samples streaming data set by using the constructed and inverted index
    def streaming_data_sampling(self,inverted_index="inverted_index_5000",streaming_dir="streaming2"):
         
        f1 = open(os.path.join(inverted_index), "rb") 
        inverted_dict = pickle.load(f1)
        f1.close()
 
        #id_list = inverted_dict['list']
        #print("matched ids " + str(len(id_list)))

                 
        for keyword,_ in inverted_dict.items():
            self.freq[keyword] = 0

        print("Generate streaming documents\n")
        for file_counter in range(1,100001):

            keyword_set = list([])

            while(True):
                keyword_set = random.sample(list(inverted_dict),5)
                if("list" not in keyword_set):
                    break
   
            for key in keyword_set:
                self.freq[key] +=1

            line = "list,"
            line += ",".join(keyword_set)
            self.freq["list"] +=1

            #write the file and keyword_set to the file
            with open(os.path.join(streaming_dir, str(file_counter)), "a+") as myfile:
                myfile.write(line)

        

        #dump frequencies to file
        with open('freq.csv', 'w') as csv_file:
            writer = csv.writer(csv_file)
            for w in sorted(self.freq, key=self.freq.get, reverse=True):
                writer.writerow([w, self.freq[w]])

        print("Completed")


if __name__ == '__main__':
    app = StreamingSet(1000)
    app.streaming_data_sampling()