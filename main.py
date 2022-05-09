from os import name

from scapy import all
from binascii import *

from scapy.compat import raw
from scapy.libs import ethertypes
from scapy.utils import rdpcap


def byt_int(bytes):
    result = 0
    for b in bytes:
        result = result * 256 + int(b)
    return result

def main():
    file = rdpcap("vzorky_pcap_na_analyzu/trace-26.pcap")
    text = ""
    counter = 0
    counterLLDP=0
    output2 = []
    w=[]
    for pack in file:
        counter = counter + 1
        print("\nrámec number", counter)
        print("dĺžka rámca poskytnutá pcap API –", pack.wirelen, "B")
        po_len = pack.wirelen

        if (po_len >= 64):
            po_len = po_len + 4
        elif (po_len <= 60):
            po_len = 64


        print("dĺžka rámca prenášaného po médiu – ", po_len)
        rawstr = hexlify(raw(pack)).decode()
        reducn = ' '.join([rawstr[i:i+2] for i in range(0, len(rawstr), 2)]).upper()
        reduc = ' '.join([reducn[i:i+24] for i in range(0, len(reducn), 24)])
        reduc = ''.join("\n" if i % 50 == 0 else char for i, char in enumerate(reduc, 1))

        print("Zdrojová MAC adresa:", reducn[18:35])
        print("Cieľová MAC adresa: ", reducn[0:17])
        file1=open("ethertype.txt", 'r')
        file2 = open("802_types.txt", 'r')
        file3 = open("ipv4.txt", 'r')
        val="undefined"
        key="undefined"
        ether_type = byt_int(raw(pack)[12:14])
        IPv4=0;
        velkost=0;
        if(ether_type >= 1536):
            print("Ethernet II")
            if(rawstr[24:26]=="88"):
                if (rawstr[26:28] == "cc"):
                    output2.append(counter)
                    counterLLDP+=1
            for line in file1:
                if len(line.split((" "),1)) == 2:
                    (key, val) = line.split((" "),1)
                    val=val[:-1]
                rez = (rawstr[24:26]+rawstr[26:28])
                if rez == key:
                    if key=="0800":
                        IPv4=1
                    print(val)
            if(IPv4==1):
                for line in file3:
                    if len(line.split((" "), 1)) == 2:
                        (key, val) = line.split((" "), 1)
                        val = val[:-1]
                    hexd=(rawstr[46:48])
                    rez2 = int(hexd, 16)
                    if str(rez2) == key:
                        print("Protocol:"+val)
                        velkost=int(rawstr[28:29])*int(rawstr[29:30])
                        print("velkost IPv4 hlavicky:"+str(velkost)+" bytes")
                        print("Source Adress is:"+str(int(rawstr[52:54],16))+'.'+str(int(rawstr[54:56],16))+'.'+str(int(rawstr[56:58],16))+'.'+str(int(rawstr[58:60],16)))
                        text=text+(str(int(rawstr[52:54],16))+'.'+str(int(rawstr[54:56],16))+'.'+str(int(rawstr[56:58],16))+'.'+str(int(rawstr[58:60],16))+" ")
                        print("Destination Adress is:" + str(int(rawstr[60:62], 16)) + '.' + str(int(rawstr[62:64], 16)) + '.' + str(int(rawstr[64:66], 16)) + '.' + str(int(rawstr[66:68], 16)))
                        print("Source port is:"+str(int(rawstr[68:72], 16)))
                        print("Destination port is:" + str(int(rawstr[72:76], 16)))
            IPv4=0

        elif (ether_type <= 1500):
            type = rawstr[28:30]
            if (type == "aa"):
                print("IEEE 802.3 s SNAP")
                for line in file2:
                    if len(line.split((" "), 1)) == 2:
                        (key, val) = line.split((" "), 1)
                        val = val[:-1]
                    rez = (rawstr[40:42])
                    if rez == key:
                        print(val)

            elif (type == "ff"):
                print("IEEE 802.3 Raw")

            else:
                print("IEEE 802.3 s LLC")

        else:
            print("Undefined")

        print(reduc)
    lst_no = [',', ':', '!', '"', "'", '[', ']', '-', '—', '(', ')', '?', '_', '`']  # и т.д.
    lst = []

    for word in text.lower().split():
        if not word in lst_no:
            _word = word
            if word[-1] in lst_no:
                _word = _word[:-1]
            if word[0] in lst_no:
                _word = _word[1:]
            lst.append(_word)

    _dict = dict()
    for word in lst:
        _dict[word] = _dict.get(word, 0) + 1

    _list = []
    for key, value in _dict.items():
        _list.append((value, key))
        _list.sort(reverse=True)

    output = []
    for w in text.split():
        if w not in output:
            output.append(w)
    print("Ramcy:")
    print(output2)
    print("Pocet ramcov:")
    print(counterLLDP)
    print('IP adresy:')
    print(output)
    print(f'Adresa uzla s najvacsim poctom odoslanych paketov:: `{_list[0][1]}`, `{_list[0][0]}` paketov.')
main()
