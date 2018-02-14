import re, operator
import collections
from hackVigenere_guma9188 import encryptVigenere, getSubStrings_usingDifferentKeyLen 

engLetterFreq = {'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702, 'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.996, 'J': 0.153, 'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507, 'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056, 'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074}
plainText = """ethicslawanduniversitypoliciestodefendasystemyouneedtobeabletothinklikeanattackerandthatincludesunderstandingtechniquesthatcanbeusedtocompromisesecurityhoweverusingthosetechniquesintherealworldmayviolatethelawortheuniversitysrulesanditmaybeunethicalundersomecircumstancesevenprobingforweaknessesmayresultinseverepenaltiesuptoandincludingexpulsioncivilfinesandjailtimeourpolicyineecsisthatyoumustrespecttheprivacyandpropertyrightsofothersatalltimesorelseyouwillfailthecourseactinglawfullyandethicallyisyourresponsibilitycarefullyreadthecomputerfraudandabuseactcfaaafederalstatutethatbroadlycriminalizescomputerintrusionthisisoneofseverallawsthatgovernhackingunderstandwhatthelawprohibitsyoudontwanttoenduplikethisguyifindoubtwecanreferyoutoanattorneypleasereviewitsspoliciesonresponsibleuseoftechnologyresourcesandcaenspolicydocumentsforguidelinesconcerningproperuseofinformationtechnologyatumaswellastheengineeringhonorcodeasmembersoftheuniversitycommunityyouarerequiredtoabidebyt"""
keys = ['yz', 'xyz', 'wxyz', 'vwxyz', 'uvwxyz']

def find_Mean_Dict(inDict):
    mean = 0
    for key, value in inDict.items():
        mean += value
    mean = mean/len(inDict)
    return round(mean,6)

def find_Mean_List(inList):
    mean = 0
    for value in inList:
        mean += value
    mean = mean/len(inList)
    return round(mean,6)

def extract_ValueList_FromDict(inDict):
    valuesList = []
    for key, value in inDict.items():
        valuesList.append(value)
    return valuesList

def populationVariance(populationList, populationMean):
    #print ("Population list: ",populationList, "Population Mean: ",populationMean)
    sum = 0
    for i in range(len(populationList)):
        sum += ((populationList[i] - populationMean)**2)
    populationVariance = sum / len(populationList);
    return round(populationVariance,6)

def getDict_relativeFreq_FromPlaintext(plainText):
    plainText = plainText.upper()
    plainText_letterFreq = {}
    for char in range(ord('A'),ord('Z')+1):
        plainText_letterFreq[chr(char)] = 0
    for char in plainText:
        plainText_letterFreq[char] += 1
    #print (plainText_letterFreq)
    plainText_len = len(plainText)   
    #print ("Len: ",plainText_len)
    for key,value in plainText_letterFreq.items():
        plainText_letterFreq[key] = round((value/plainText_len)*100,6)
    #print (plainText_letterFreq)
    return plainText_letterFreq
    
def populationVariance_fromPlainText(plainText):
    freq_dict = getDict_relativeFreq_FromPlaintext(plainText)
    return populationVariance(extract_ValueList_FromDict(freq_dict),find_Mean_Dict(freq_dict))


def get_populationVariance_trend(plainText, key_list):    
    cipherText_dict = {}
    for keys in key_list:
        cipherText_dict[keys] = populationVariance_fromPlainText(encryptVigenere(plainText, keys))

    #print ("Ciphers: ",cipherText_dict)
    return cipherText_dict
    

def part_d(plainText,key_list):
    key_ciphers_dict = {}
    for keys in key_list:
        key_ciphers_dict[keys] = encryptVigenere(plainText, keys)
    #print ("Key ciphers dict: \n",key_ciphers_dict)
    key_var = {}
    for keys in key_list:
        separated_ciphers = []
        separated_ciphers = (getSubStrings_usingDifferentKeyLen(len(keys),key_ciphers_dict[keys]))
        #print ("Separated ciphers: \n",separated_ciphers)
        variance = []
        for ciphers in separated_ciphers:
            #print ("\nCiphers \n",ciphers)
            #print ("Var: ",populationVariance_fromPlainText((ciphers)))
            variance.append(populationVariance_fromPlainText(ciphers))
        key_var[keys] = variance
    #print ("KEY:VAR ",key_var)

    key_varMean = {}
    for keys, value in key_var.items():
        key_varMean[keys] = find_Mean_List(value)
    print ("Part d: \n{KEY:VAR_MEAN}\n",key_varMean)

def part_e(plainText,key):
    cipherText_List = []
    key_ciphers_dict = {}
    key_ciphers_dict[key] = encryptVigenere(plainText,key )
    cipherText_List.append(encryptVigenere(plainText, key))

    key_var = {}
    for key_len in range(1,len(key)*3+1):
##    for key_len in range(2,6):
        separated_ciphers = []
        separated_ciphers = (getSubStrings_usingDifferentKeyLen(key_len,key_ciphers_dict[key]))
        #print ("Separated ciphers: \n",separated_ciphers)
        variance = []
        for ciphers in separated_ciphers:
            #print ("\nCiphers \n",ciphers)
            #print ("Var: ",populationVariance_fromPlainText((ciphers)))
            variance.append(populationVariance_fromPlainText(ciphers))
        key_var[key_len] = variance

    #print ("KEY:VAR ",key_var)

    key_varMean = {}
    for keys, value in key_var.items():
        key_varMean[keys] = find_Mean_List(value)
    print ("Part e [Key = %s]: \n{KEY:VAR_MEAN}\n" %key,key_varMean)
    

    
def problem2():       
    print ("Part a: Var of English Text: ",populationVariance(extract_ValueList_FromDict(engLetterFreq),find_Mean_Dict(engLetterFreq)))
    print ("Part b: Var of Given Plain Text: ",populationVariance_fromPlainText(plainText))
    print ("Part c: Trends of Variance for keys: \n",get_populationVariance_trend(plainText,keys))
    part_d(plainText,keys)
    part_e(plainText,"uvwxyz")

if __name__ == "__main__":
    problem2()
