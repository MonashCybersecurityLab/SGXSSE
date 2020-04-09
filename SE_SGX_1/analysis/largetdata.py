import os
import operator
import pickle
import random, csv
from sklearn import preprocessing
import numpy as np
from random import choices

#public freq can be accessed at https://norvig.com/ngrams/
#follow the zipf law distribution 1/n ranking

class LargeStreamingSet:
 
    def read_distribution(self,ds,NewMin,NewMax,Top,streaming_dir):
        #parse cluster_checking_points
        freq_file = open(os.path.join(ds), "r")
        reader = csv.reader(freq_file,delimiter=',')
        keyword_set = []
        freq_set = []

        top_counter = 0 
        for row in reader:
            if(top_counter <=Top):
                keyword_set.append(row[0])
                freq_set.append(int(row[1]))
                top_counter +=1
            else:
                break

        #scale to new range [NewMin,NewMax]
        OldMax = max(freq_set)
        OldMin = min (freq_set)
        OldRange =  OldMax - OldMin
        NewRange = (NewMax - NewMin)  

        scaled_set = []
        for value in freq_set:
            NewValue = int((((value - OldMin) * NewRange) / OldRange) + NewMin)
            scaled_set.append(NewValue)

        #print distribution into .csv file
        with open('freq_zipf.csv', 'w') as csv_file:
            writer = csv.writer(csv_file)
            for index, keyword in enumerate(keyword_set): 
                writer.writerow([keyword, scaled_set[index]])
        csv_file.close()

        # for each docId from NewMin to NewMax
        # consider the occurance of all keywords, then update its freq decreased by 1
        # or using the blog ds
        for file_counter in range(1,NewMax):
            cur_doc_keywords = list([])
            for index, keyword in enumerate(keyword_set): 
                if(scaled_set[index]>0):
                    cur_doc_keywords.append(keyword)
                    scaled_set[index] -=1
            
            mylist = list( dict.fromkeys(cur_doc_keywords))    
            line = ",".join(mylist)
            
            #write the file and keyword_set to the file
            with open(os.path.join(streaming_dir, str(file_counter)), "a+") as myfile:
                myfile.write(line)
            
            myfile.close()

        print("Completed generating " + str(file_counter) + "docs ")
   

if __name__ == '__main__':
    app = LargeStreamingSet()
    app.read_distribution(ds = "count_1w.csv",NewMin=1,NewMax=50000000,Top = 100000, streaming_dir="streaming")