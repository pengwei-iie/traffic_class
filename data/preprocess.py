from scapy.all import *
from tqdm import tqdm
import json


FILE_NAME = 'vpn'
NOR_OR_NOT = 0  # nonvpn 1 or vpn 0


def projection_to_clss(file_name):
    if 'youtube' in file_name.lower():
        tmp = 'youtube'
    elif 'email' in file_name.lower():
        tmp = 'email'
    elif 'facebook' in file_name.lower():
        tmp = 'facebook'
    elif 'ftp' in file_name.lower():
        tmp = 'ftp'
    elif 'hangout' in file_name.lower():
        tmp = 'hangout'
    elif 'bittorrent' in file_name.lower():
        tmp = 'bittorrent'
    elif 'netflix' in file_name.lower():
        tmp = 'netflix'
    elif 'skype' in file_name.lower():
        tmp = 'skype'
    elif 'spotify' in file_name.lower():
        tmp = 'spotify'
    elif 'vimeo' in file_name.lower():
        tmp = 'vimeo'
    elif 'voipbuster' in file_name.lower():
        tmp = 'voipbuster'
    return tmp

# 从pcap文件读取数据包,转换为字符串,保存到文本文件
def get_str():
    # 获取当前工作目录
    nowpath = os.getcwd() + r'/'[0]
    print('nowpath: ', nowpath)
    # 要处理的文件夹
    folders = [FILE_NAME]

    for i in range(len(folders)):
        # 获取文件夹下的所有pcap文件
        filenames = os.listdir(nowpath + folders[i])
        foldersinfo = []
        print(i + 1, end=' ')
        print(len(filenames))
        for each in tqdm(filenames):
            # # add
            # if os.(each):
            #     inner_files = os.listdir(each)
            #     for inner_each in inner_files:
            #         filename = nowpath + folders[i] + r'/'[0] + inner_each
            #         tmp = each.split('-')[0]
            # # add
            filename = nowpath + folders[i] + r'/'[0] + each
            tmp = each.split('.p')[0]
            with open(nowpath + folders[i] + r'/'[0] + tmp + '.txt', 'w', encoding='utf-8') as f:
                try:
                    # 读取pcap文件
                    pr = PcapReader(filename)
                except:
                    print('file ', filename, '  error')
                    continue
                pkt = 1
                while pkt:
                    try:
                        # 从pcap文件中读取一个数据包,逐个读取pcap文件中的数据包
                        pkt = pr.read_packet()
                        if 'Raw' in pkt:
                            # 将scapy的数据包pkt转化为一个可打印可处理的字符串
                            f.write(str(repr(pkt)) + '\n')
                    except EOFError:
                        break

        # with open(nowpath + folders[i] + r'/'[0] + tmp+'.txt', 'a') as f:
        #     f.write(str(foldersinfo))


# 将文本文件中的字符串分割成词元,生成三元组训练样本
def triplet_tokens():
    # 多个文件路径，每一个文件夹下放一类的数据（如正常异常分类、12类应用分）
    # 如果只做应用分类，就写一个就行
    # and if the apps are all vpn, directly set label as 1: 0
    adrs = [FILE_NAME]
    # 不用管
    datasets = []
    # add
    num_dict = {'email': 0, 'facebook': 0, 'ftp': 0, 'hangout': 0, 'bittorrent': 0, 'netflix': 0, 'skype': 0, 'spotify': 0, 'vimeo': 0, 'voipbuster': 0, 'youtube': 0}
    for name in os.listdir(adrs[0]):
        if 'txt' in name:
            tmp = name.split('.txt')[0]
            datasets.append(tmp)
    # add
    for i in range(len(adrs)):
        # 根据i的不同，设置不同的分类类别; vpn is set to 0
        if i == 0:
            clss1 = {'youtube': 0, 'email': 1, 'facebook': 2, 'ftp': 3, 'hangout': 4, 'bittorrent': 5, 'voipbuster': 6, 'netflix': 7, 'skype': 8, 'spotify': 9, 'vimeo': 10}
            datasets = datasets
        elif i == 1:
            clss1 = {'normal': 0, 'abnormal': 1}
            datasets = ['normal', 'abnormal']
            pass
        # 遍历每一个类别下的数据集，循环twitter、youtube等
        for j in range(len(datasets)):
            # d 表示某个应用（twitter）或者恶意
            d = datasets[j]
            # 拿到adr->packets
            adr = adrs[i] + r'/'[0] + d + '.txt'
            f = open(adr, encoding='utf-8')
            lines = [line.strip() for line in f.readlines()]
            # fixme just a sample 只取前1000条数据，正式处理时删除
            lines = lines[:14345]
            # 用来存过滤后的数据和label，同时保存对比损失所需要的样本
            data = {}
            for line in tqdm(lines):
                # 对每行进行词元分割
                text = re.split(r'\\| ',line)
                # 进行过滤
                for k in range(len(text)):
                    if 'src' in text[k] or 'dst' in text[k] or 'port' in text[k]:
                        text[k]=''
                # no need
                if i == 0:
                    # deal with d, cause d is the name of txt file, make a projection to clss1
                    new_d = projection_to_clss(d)
                    label1 = clss1[new_d]
                    num_dict[new_d] += 1
                elif i == 1:
                    new_d = projection_to_clss(d)
                    label1 = clss1[new_d]
                if i == 0:
                    tmp = {"text": list(filter(None, text)),
                       "label": {0: clss1[new_d], 1: NOR_OR_NOT, 2: None, 3: None, 4: None, 5: None}}
                elif i == 1:
                    tmp = {"text": list(filter(None, text)),
                       "label": {0: clss1[new_d], 1: NOR_OR_NOT, 2: None, 3: None, 4: None, 5: None}}
                # keep consistent to the structure of the training sets, although we donot use the positive and negative part in the test.
                # fix bug
                # tr = {"anchor": tmp, "positive": tmp, "negative": tmp}
                tr = {"anchor": tmp}
                tr = json.dumps(tr, ensure_ascii=False)
                # 把一个类的放在一起，“0”对应一系列的list，“1”也是对应一系列的list
                if str(label1) not in data:
                    data[str(label1)] = [tr]
                else:
                    data[str(label1)].append(tr)
            print('file ', adr, 'num is: ', )
            # 对“0”中的每一个样本存储一行，再“1”
            w = open(adrs[i]+'all.txt', 'a', encoding='utf-8')
            for tmp in data:
               w.write('\n'.join(str(v) for v in data[tmp]))
        print(num_dict)

# 1. from pcap to str
get_str()

# 2. split into tokens and produce 'text.txt'
triplet_tokens()

# 3. test in the pretrain
# put the text.txt into the model
