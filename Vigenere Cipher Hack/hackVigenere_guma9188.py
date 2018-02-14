import re, operator
import collections
from itertools import permutations

engLetterFreq = {'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702, 'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.996, 'J': 0.153, 'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507, 'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056, 'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074}

cipherText= """DFSAWSXSOJSBMJUVYAUETUWWPDRUTHOOBSWUSWSQMHVSMQRVJFQOCHGFNAOYLGRUWIYLRKISJCHWVOQYZIXYJFXADVKJSMNDPCFRUOYIITOLTHWDPFYRHRVSOFWBMKJGUMRYKDCHDWVLDHCYJEEEOHLOCQJBAAUSKPQIWVXYBHIGHVTPAYEKIZOTFFHRTFCZLGZVSGUCLIJBBXHKMTIOLPUICBHYOWSMBFCZXWRTDYNWWZOWHQRVDBHCZQWVDILTWCJVQBLVHRUOWZQJZESHELECJHSODXRJBNPJVZUMUFWLVOHCNDXZPBUYGRFOFYAXHZBHCZQQFESLYFVPQHIRUEGIMCYWIITSWEVXYFRCDFMGMWHPVSWNONSHQRUWWDFSDQINPUWTJSHNHEEESFPFXIJQUWHRXJBYPUMEHAIOHVEDFSAWSXSOJSBMJISUGLPPCOMPGSENONSHQRUWWLOXYFCLJDRUDCGAXXVSGWTHRTFDLLFXZDSWCBTKPULLSLZDOFRRVZUVGDDVVESMTJRVEOLZXRUDCGAXXRUWIYDPYBFXYHWJBGMFPTKJCHDPEBJBADXGYBZAZUMKIAMSDVUUCVCHEBJBJCDGKJQYMBEEZOXGHVJBFSTWMJUVYZUIKJQUWOCGPGMTEPVUCVCHEBTIWSDWPTHYXEYKJHCDLRWFOMTEPVUCXZVSSZOHJNRFXBJCDGKJQUWPIROGWCBTKPZIRBVVMONPGXVDVHZOSXZVUDUEZTSXLQYDCSLZIPVHOFTVWLFGNSHICFQNCRRZDTLZQXZFFZZXRUBHCZQARTWHGRPMFRCYDGRTSCYWLVVBCEHHJUONPVAYJQBBXIJUWIYHHNISNSHVIFEOTUMEHGODSITUSXNUMDJBUWVXFQFIGLHVUVYTUHVDFSAWMFOYYJVXFMOQPQJFSQYXHRKJGOYFSETHCEXXZPBUWWLVFTZLUKLFRNSDXKIWMTVEMJCFLWMFOCZEKIIJUBERJEPHVPLRXGCLNHHKPWHNUMDJBUEHSEFGYWIEJHWPPQMEUVYQLJKIOGPQHD"""


def getDict_relativeFreq_FromPlaintext(plainText):
    plainText = plainText.upper()
    plainText_letterFreq = {}
    for char in range(ord('A'),ord('Z')+1):
        plainText_letterFreq[chr(char)] = 0
    for char in plainText:
        plainText_letterFreq[char] += 1
    plainText_len = len(plainText_letterFreq)
    for key,value in plainText_letterFreq.items():
        plainText_letterFreq[key] = round((value/10),4)
    return plainText_letterFreq

#we get the frequency dictionary for the plaintext and compare it with that of the english frequencies dictionary using a Chi-squared statistics
def freq_analysis_withEnglish(plainText):
    freqA_dict = getDict_relativeFreq_FromPlaintext(plainText)
    freqB_dict = engLetterFreq
    chi_stat = 0
    for char in range(ord('A'),ord('Z')+1):
        chi_stat += round((((freqA_dict[chr(char)] - freqB_dict[chr(char)])**2) / freqB_dict[chr(char)]),4)
    return chi_stat
    
def decryptVigenere(cipherText, key):
    itr = 0
    plainText =""
    for i in cipherText:
        #print ("I = " +str(ord(i)) + " = " + str(i) + " KEY = " + str(ord(key[itr%len(key)])) + " " + str(key[itr%len(key)]))
        diff = ord(i) - ord(key[itr%len(key)])
        if diff < 0:
            diff += 26
        #print ("a = " +str(diff+65) +" = " + str(chr(diff+65)))
        plainText += chr(diff+65)
        itr = itr+1;
    return (plainText)

def encryptVigenere(plainText, key):
    itr = 0
    cipherText =""
    for i in plainText:
        #print ("I = " +str(ord(i)) + " = " + str(i) + " KEY = " + str(ord(key[itr%len(key)])) + " " + str(key[itr%len(key)]))
        a = ((ord(key[itr%len(key)]) - 65) + (ord(i) - 65)) % 26
        #print ("a = " +str(a+65) +" = " + str(chr(a+65)))
        cipherText += chr(a+65)
        itr = itr+1;
    return (cipherText)

def get_factors(number):
    # This function takes a number and prints the factors
    factors = []
    for i in range(2, number + 1):
       if number % i == 0:
           factors.append(i)
           #print(i)
    return factors
           

def findRepeatingSeq(cipherText, repeatingSeq):
    reccurence_StartPos = []
    for m in re.finditer(repeatingSeq, cipherText):
        #print(repeatingSeq, ' found at', m.start(), m.end())
        reccurence_StartPos.append(m.start())
        
    if len(reccurence_StartPos) < 2:
        return []
    
    len_diff = []
    #from first to last
    for i in range(len(reccurence_StartPos)-1):
        for k in reccurence_StartPos[i+1:]:
            len_diff.append(abs(reccurence_StartPos[i]-k))
            
    #removing duplicates
    len_diff = list(set(len_diff))
    return len_diff
    

#finds the recurring sequences in the cipherText
#it then finds the difference in spaces between each recurring sequences
#it combines and creates a list of all the difference in spaces and returns it
def getDiffBetweenRepeatingSeq(cipherText):
    lenDiff = []
    #for i in range(3,len(cipherText)/2):
    for i in range(3,15):
        for k in range(0,len(cipherText)-i):
            tempString = cipherText[k:k+i]
            lenDiff += findRepeatingSeq(cipherText,tempString)
    
    lenDiff = list(set(lenDiff))
    return lenDiff

#gets all the factors of the numbers available in the parameter list and returns a sorted list of all the combined factors
def getFactorsOfSpacings(lenDiff_list):
    factors = []
    for number in lenDiff_list:
        factors += get_factors(number)
    factors.sort()
    return factors

def getList_MaxValue_inDict(inDict):
    maxValueList = []
    value_n_minus_1 = 0
    inDict2 = sorted(inDict.items(), key=operator.itemgetter(1), reverse=True)
    for key, value in inDict2:
        if value >= value_n_minus_1:
            maxValueList.append(key)
            del inDict[key]
        else:
            break;
        value_n_minus_1 = value
    
    value_n_minus_1 = 0
    inDict = sorted(inDict.items(), key=operator.itemgetter(1), reverse=True)
    for key, value in inDict:
        if value >= value_n_minus_1:
            maxValueList.append(key)
        else:
            break;
        value_n_minus_1 = value
        
    return maxValueList

def getDict_MaxKeyValue_inDict(inDict):
    maxKeyValue_dict = {}
    value_n_minus_1 = 0
    inDict = sorted(inDict.items(), key=operator.itemgetter(1), reverse=True)
    for key, value in inDict:
        if value >= value_n_minus_1:
            maxKeyValue_dict[key] = value;
        else:
            break;
        value_n_minus_1 = value
    return maxKeyValue_dict

def getList_MaxKey_inDict(inDict):
    maxKey_list = []
    value_n_minus_1 = 0
    inDict = sorted(inDict.items(), key=operator.itemgetter(1), reverse=True)
    for key, value in inDict:
        if value >= value_n_minus_1:
            maxKey_list.append(key);
        else:
            break;
        value_n_minus_1 = value
    return maxKey_list

def getList_MinKey_inDict(inDict):
    minKey_list = []
    value_n_minus_1 = 0
    inDict = sorted(inDict.items(), key=operator.itemgetter(1), reverse=False)
    for key, value in inDict:
        minKey_list.append(key)
        break;
    return minKey_list

def guess_keyLen(factors_dict):
    keyLen_guess = []
    keyLen_guess = getList_MaxValue_inDict(factors_dict)
    return keyLen_guess

#we return the separated strings from the cipherText depending on the key lenght. So basically we divide the cipherText in "keyLen_guess" parts
def getSubStrings_usingDifferentKeyLen(keyLen_guess, cipherText):

    strings = []
    for i in range(keyLen_guess):
        tempString= ""
        for chars in cipherText[i::keyLen_guess]:
            tempString += chars
        strings.append(tempString)
    return strings


#We decrypt each separated cipherText with letters A-Z and use frequency analysis on each of those decrypted strings and find the specific set of key 	guesses for that particular position   
#We get the first 2 minimum stat 
def get_SubKeyGuesses(strings):
    subKeys_list = []
    for s in strings:
        freq_dict = {}
        for alpha in range(ord('A'),ord('Z')+1):
            plainText = decryptVigenere(s,chr(alpha))
            stat = freq_analysis_withEnglish(plainText)
            freq_dict[chr(alpha)] = stat
        subKeys_list.append(getList_MinKey_inDict(freq_dict))
    return subKeys_list


def getPermutations_special(inList,initial):
    guess=[]
    if(len(inList)==0):
        return []
    if (len(inList)==1):
        for i in inList[0]:
            guess.append(initial+i)
        return guess
    if(len(inList)>1):
        for i in inList[0]:
            guess=guess+getPermutations_special(inList[1:],initial+i)
    return guess

    
def hackVigenere_withoutKey(cipherText):
    print ("*"*80)
    print ("CipherText: ",cipherText)
	#getting factors list of the spacings found between recurring sequences in the cipherText
    factors_list = getFactorsOfSpacings(getDiffBetweenRepeatingSeq(cipherText))
    #print (factors_list)
	#we create a dictionary of all the factors and its frequencies in the factors_list
    factors_counter = collections.Counter(factors_list)
    #print (factors_counter)
	#we guess the key len from taking the 2 highest frequency numbers in the factors_list 
    keyLen_guess = guess_keyLen(factors_counter)
    print ("Key Len Guess: ", keyLen_guess)
	#iterate over each key len guess
    for key in keyLen_guess:
		#we get separated cipherText depending on the key length.
		#e.g. if the key length is 2, we get two different string from the cipherText. First with all the odd positioned letters and Second the even positioned.
        strings_list = getSubStrings_usingDifferentKeyLen(key,cipherText)
        subKeys_list = []
        subKeys_list = get_SubKeyGuesses(strings_list)
        print ("Subkey Guesses: ",subKeys_list);
		#we find the permutations for all the key sets
        key_guesses = getPermutations_special(subKeys_list,"")
        print("KeyLen: ",key," Guess: " ,key_guesses)
        for keyGuess in key_guesses:
            plainText = decryptVigenere(cipherText,keyGuess)
            print ("PlainText: ",plainText)
    print ("*"*80)
    
if __name__ == "__main__":
	hackVigenere_withoutKey(cipherText)
