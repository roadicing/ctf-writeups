#!/usr/bin/env sage

import random
from tqdm import tqdm
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes

n, q = 263, 128
Zx.<x> = ZZ[]

def convolution(f,g):
    return (f * g) % (x^n-1)

def balancedmod(f,q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g)  % (x^n-1)

def randomdpoly(d1, d2):
    result = d1*[1]+d2*[-1]+(n-d1-d2)*[0]
    random.shuffle(result)
    return Zx(result)

def decode(poly):
    coeffs = poly.list()
    val = sum([(coeffs[i] + 1) * 3 ^ i for i in range(len(coeffs))])
    return val

f = open("data", "r")

ct_flag = sage_eval(f.readline().strip(), locals={'x':x})
pk = sage_eval(f.readline().strip(), locals={'x':x})

pt_list = []
ct_list = []
for _ in range(200):
    tmp = f.readline().strip().split(" ", 1)
    pt_list.append(long_to_bytes(int(tmp[0], 16), 240 // 8))
    ct_list.append(sage_eval(tmp[1], locals={'x':x}))

state_data = []
for pt in pt_list:
    tmp = pt[2:]
    for i in range(28, 0, -4):
        state_data.append(Integer(bytes_to_long(tmp[i - 4: i]) >> 16))
    state_data.append(Integer(bytes_to_long(pt[:2])))

'''
# https://github.com/JuliaPoo/MT19937-Symbolic-Execution-and-Solver

import sys
sys.path.append('./source')

from MT19937 import MT19937

states = MT19937(state_from_data = (state_data, 16)).state

print(states)

# [2147483648, 3304395405, 1246066023, 1346102213, 1462062998, 1724213779, 495182607, 2856467894, 1122100683, 3457842173, 2384200523, 1803760811, 3290832821, 4277760004, 4203945960, 151121913, 1471711993, 2641607132, 102878469, 574111724, 3226817060, 3087426128, 1687321663, 1444315492, 1836929113, 2920125814, 2070577354, 2839659865, 379178659, 3126776161, 3543805300, 3815173844, 3073114378, 2605612860, 4118989325, 1516148690, 773626291, 3037103354, 1536060224, 3205451419, 2042534366, 262841608, 2872864387, 958261747, 3238783418, 178267393, 314085719, 686736920, 1768439597, 3418532022, 2679040189, 2711474852, 2911147486, 2910683478, 1762862934, 1447415143, 680061475, 2059727620, 3669719124, 3211047697, 2309112205, 2171869169, 571699730, 764556554, 4172079824, 1464729945, 791868750, 20268428, 2952423979, 834174383, 3920842767, 2852632235, 772951766, 259534545, 1485617347, 1357781475, 4153896190, 1490745104, 2582557391, 2586860218, 3366078536, 4273924333, 3134437433, 2599917767, 3658113806, 1971811573, 3846016415, 119636642, 4028536480, 48217355, 2074868268, 3479792967, 3661258605, 4218880923, 90912392, 1420583539, 1047036693, 1031455621, 1196983145, 1981774570, 1898154992, 300855855, 3201789228, 1803710947, 389839649, 2829115220, 3370112586, 306538908, 1337820788, 2631632190, 1222677143, 1112101227, 2911607885, 1248207204, 1802218943, 2900311431, 3736121151, 1814377598, 413604534, 4261938978, 786532649, 1131628278, 853350530, 811790741, 3038281679, 1994220929, 4035664517, 2410753751, 2665549923, 592295972, 2517217991, 3884788112, 1454809323, 3633305028, 3492721895, 1907688992, 1032160701, 2397055011, 2066832266, 3885824154, 3533965798, 1235124591, 1875676147, 3364615708, 2626378899, 430184839, 657054373, 2957911743, 1347815767, 1709771438, 3855834871, 192578730, 1953011562, 1049508241, 4032884878, 1971405809, 343676439, 2723000420, 1052783469, 312936963, 687904954, 1652986662, 2803300224, 689290120, 888469799, 902540115, 1923967696, 870451362, 1246110108, 922612524, 3910290604, 4232252531, 859637135, 1015595060, 3289798893, 514152897, 1788948446, 902505430, 2741079117, 3595079160, 4025169419, 859568410, 1626051799, 3606098689, 1798138006, 4099456821, 828281352, 4142068955, 1278075718, 2245483237, 3343302819, 4181530263, 3390364653, 3159096329, 3163496296, 1680198864, 838827886, 391709298, 4077027283, 662848630, 1507999277, 3777739445, 1965176825, 497736645, 1336524480, 53303342, 915604667, 2162786884, 2396315972, 1841552799, 543953446, 2067290914, 2729817307, 2132994242, 1310625807, 6101311, 3447194251, 442008394, 4138051127, 4280742129, 435719823, 574033635, 314773693, 2851099063, 3644369989, 288769063, 1201005134, 1932274675, 308092698, 546483631, 2524488275, 900353146, 3456593312, 2479293412, 2016166954, 3453211607, 2949696084, 4089303530, 2196177381, 3391795434, 1460439426, 1776571673, 3419333642, 2826414747, 48914873, 3851168071, 482139675, 2740069554, 1133655844, 1008373664, 607827189, 2911908346, 1193070508, 1013061612, 2722268891, 4111434100, 1967647968, 444972949, 3093534650, 2149585534, 834096415, 1958735343, 1752771167, 571952018, 242797852, 576365840, 1298625970, 3023920047, 166823541, 435056602, 3754109956, 405899009, 2700558882, 3219387258, 87264717, 1889301009, 2949583555, 684951632, 953970808, 2882235070, 1799957761, 2374633697, 1661661359, 466787101, 442828974, 3534432414, 2427571537, 1005903754, 3085307784, 159598721, 1012035748, 1083887459, 770261592, 424369693, 1349387847, 3934285874, 2150568372, 3748404039, 2272939707, 2556877371, 3566308881, 3458048329, 1502443477, 3308959594, 3846313541, 920435126, 874941721, 644750379, 1720359349, 1420840885, 2758519551, 3628313918, 3779082825, 3278480635, 261870698, 941434237, 1485723006, 3580400002, 771495396, 1532674348, 532272693, 3382679818, 1418279480, 73934606, 116653598, 2807951495, 557780441, 2091094945, 1173365508, 3502260301, 3512642482, 2983823128, 3829841939, 922464224, 2755226150, 1484106538, 2629626928, 1891258434, 3249715333, 2317478440, 3065362822, 690962321, 2512187286, 107310310, 1804223759, 1333447156, 3222250869, 2774043711, 4101509377, 1656093195, 1210498087, 1580244223, 3575090905, 1715592974, 1308964886, 1959303847, 4130338569, 755461711, 1297544196, 3384914696, 2918837418, 1496469493, 2192567665, 1821474486, 3076849101, 3865579391, 3527034692, 2689498671, 2653358007, 842349770, 3586457406, 2786747535, 578368656, 1891260975, 1958741026, 364337519, 3135888193, 3629236216, 3003114404, 845121589, 3158987799, 2885934981, 3677781562, 424398347, 3307170923, 636168575, 1857181782, 1738521206, 4014266398, 3131182162, 2252841313, 2823678462, 1585737143, 249025536, 2214716005, 964173973, 1247819089, 3822247754, 4028631134, 1046427558, 3172929050, 2774508643, 4014335927, 3367680087, 371238079, 1185853926, 3127600616, 1916052963, 1575897628, 3451058851, 2062777055, 1790667418, 394625681, 2382373632, 1285427260, 2643027723, 3123651687, 4210562860, 2711525376, 2971180694, 250367950, 18281469, 120536218, 4192947987, 3699693593, 1520329608, 1965300243, 2511166512, 2260906473, 1471672543, 1292752813, 3342751218, 1083026259, 1028770826, 897765950, 2771274302, 301031870, 3677882617, 1770162684, 2354568845, 1185428271, 1940714535, 3200296384, 2198543582, 2522249968, 4168225877, 1136266250, 1665230132, 1009666566, 2466777420, 3654387933, 3541099283, 399564888, 2029519241, 1938918846, 1998008849, 1550075810, 736109086, 1947920262, 2929137316, 3896575536, 160018438, 3287729280, 2786425677, 1978735038, 1710922518, 3276629185, 901887228, 1409381921, 1802710052, 1533198493, 2763965225, 1964572840, 3805673305, 421729960, 877445562, 4050503427, 3604482097, 3845387322, 4278931548, 283179779, 2949352089, 2103367957, 1904833415, 4265850834, 849901850, 2106067390, 2387713572, 1562826559, 3377379712, 3765702780, 3134208395, 2229885327, 1227161476, 4213661447, 2384444653, 1754919942, 525276836, 3782509164, 3431539636, 1957659380, 214224581, 1820030205, 402854320, 1312718859, 479792015, 3253927879, 2264079477, 1411545279, 3940890503, 734882519, 2307654333, 3727447050, 1000736929, 781283495, 166924185, 2003263903, 2946367810, 3475530663, 1896950144, 2017883729, 1865489600, 3153375112, 3600934309, 2554832449, 1936038731, 2090468206, 297532247, 82220793, 2108784711, 2274988801, 2158229567, 357938497, 662696344, 444372807, 291984896, 2569486546, 2349993887, 2005339277, 2362757906, 2519176885, 711983617, 2991638223, 876592362, 3163500251, 3324574670, 3127672184, 3041229993, 2414390677, 1392258194, 2794334570, 3548296436, 3011140001, 1828253493, 2351319417, 3225288707, 1106524169, 1599161189, 3062282683, 3951516442, 1121607452, 2985198106, 4026048312, 3823199301, 3796034591, 1251148600, 527027488, 2554316720, 1932632207, 4054901843, 2744653022, 466873369, 785726271, 779650487, 1228118542, 3720366317, 933141116, 366993130, 3173964277, 2736457468, 4166518218, 1133880834, 3295525464, 2873848756, 3947853880, 2785201906, 4013307888, 4151668616, 3895421817, 4157205930, 2349920505, 3388115512, 668197780, 2306697033, 2467551547, 2452535817, 3907210798, 258859797, 1652150479, 2761544991, 348823145, 598866271, 1840339092, 989877976, 3496161556, 1220481233, 3038481586, 2902977113, 3802129318, 3029637914, 1173532510, 849696056, 507093273, 3831670887, 364865188, 1633968215, 200011283, 3143165869, 3364273874, 1348429487, 1835863290, 4200007791, 1943539278, 379243637]
'''

states = [2147483648, 3304395405, 1246066023, 1346102213, 1462062998, 1724213779, 495182607, 2856467894, 1122100683, 3457842173, 2384200523, 1803760811, 3290832821, 4277760004, 4203945960, 151121913, 1471711993, 2641607132, 102878469, 574111724, 3226817060, 3087426128, 1687321663, 1444315492, 1836929113, 2920125814, 2070577354, 2839659865, 379178659, 3126776161, 3543805300, 3815173844, 3073114378, 2605612860, 4118989325, 1516148690, 773626291, 3037103354, 1536060224, 3205451419, 2042534366, 262841608, 2872864387, 958261747, 3238783418, 178267393, 314085719, 686736920, 1768439597, 3418532022, 2679040189, 2711474852, 2911147486, 2910683478, 1762862934, 1447415143, 680061475, 2059727620, 3669719124, 3211047697, 2309112205, 2171869169, 571699730, 764556554, 4172079824, 1464729945, 791868750, 20268428, 2952423979, 834174383, 3920842767, 2852632235, 772951766, 259534545, 1485617347, 1357781475, 4153896190, 1490745104, 2582557391, 2586860218, 3366078536, 4273924333, 3134437433, 2599917767, 3658113806, 1971811573, 3846016415, 119636642, 4028536480, 48217355, 2074868268, 3479792967, 3661258605, 4218880923, 90912392, 1420583539, 1047036693, 1031455621, 1196983145, 1981774570, 1898154992, 300855855, 3201789228, 1803710947, 389839649, 2829115220, 3370112586, 306538908, 1337820788, 2631632190, 1222677143, 1112101227, 2911607885, 1248207204, 1802218943, 2900311431, 3736121151, 1814377598, 413604534, 4261938978, 786532649, 1131628278, 853350530, 811790741, 3038281679, 1994220929, 4035664517, 2410753751, 2665549923, 592295972, 2517217991, 3884788112, 1454809323, 3633305028, 3492721895, 1907688992, 1032160701, 2397055011, 2066832266, 3885824154, 3533965798, 1235124591, 1875676147, 3364615708, 2626378899, 430184839, 657054373, 2957911743, 1347815767, 1709771438, 3855834871, 192578730, 1953011562, 1049508241, 4032884878, 1971405809, 343676439, 2723000420, 1052783469, 312936963, 687904954, 1652986662, 2803300224, 689290120, 888469799, 902540115, 1923967696, 870451362, 1246110108, 922612524, 3910290604, 4232252531, 859637135, 1015595060, 3289798893, 514152897, 1788948446, 902505430, 2741079117, 3595079160, 4025169419, 859568410, 1626051799, 3606098689, 1798138006, 4099456821, 828281352, 4142068955, 1278075718, 2245483237, 3343302819, 4181530263, 3390364653, 3159096329, 3163496296, 1680198864, 838827886, 391709298, 4077027283, 662848630, 1507999277, 3777739445, 1965176825, 497736645, 1336524480, 53303342, 915604667, 2162786884, 2396315972, 1841552799, 543953446, 2067290914, 2729817307, 2132994242, 1310625807, 6101311, 3447194251, 442008394, 4138051127, 4280742129, 435719823, 574033635, 314773693, 2851099063, 3644369989, 288769063, 1201005134, 1932274675, 308092698, 546483631, 2524488275, 900353146, 3456593312, 2479293412, 2016166954, 3453211607, 2949696084, 4089303530, 2196177381, 3391795434, 1460439426, 1776571673, 3419333642, 2826414747, 48914873, 3851168071, 482139675, 2740069554, 1133655844, 1008373664, 607827189, 2911908346, 1193070508, 1013061612, 2722268891, 4111434100, 1967647968, 444972949, 3093534650, 2149585534, 834096415, 1958735343, 1752771167, 571952018, 242797852, 576365840, 1298625970, 3023920047, 166823541, 435056602, 3754109956, 405899009, 2700558882, 3219387258, 87264717, 1889301009, 2949583555, 684951632, 953970808, 2882235070, 1799957761, 2374633697, 1661661359, 466787101, 442828974, 3534432414, 2427571537, 1005903754, 3085307784, 159598721, 1012035748, 1083887459, 770261592, 424369693, 1349387847, 3934285874, 2150568372, 3748404039, 2272939707, 2556877371, 3566308881, 3458048329, 1502443477, 3308959594, 3846313541, 920435126, 874941721, 644750379, 1720359349, 1420840885, 2758519551, 3628313918, 3779082825, 3278480635, 261870698, 941434237, 1485723006, 3580400002, 771495396, 1532674348, 532272693, 3382679818, 1418279480, 73934606, 116653598, 2807951495, 557780441, 2091094945, 1173365508, 3502260301, 3512642482, 2983823128, 3829841939, 922464224, 2755226150, 1484106538, 2629626928, 1891258434, 3249715333, 2317478440, 3065362822, 690962321, 2512187286, 107310310, 1804223759, 1333447156, 3222250869, 2774043711, 4101509377, 1656093195, 1210498087, 1580244223, 3575090905, 1715592974, 1308964886, 1959303847, 4130338569, 755461711, 1297544196, 3384914696, 2918837418, 1496469493, 2192567665, 1821474486, 3076849101, 3865579391, 3527034692, 2689498671, 2653358007, 842349770, 3586457406, 2786747535, 578368656, 1891260975, 1958741026, 364337519, 3135888193, 3629236216, 3003114404, 845121589, 3158987799, 2885934981, 3677781562, 424398347, 3307170923, 636168575, 1857181782, 1738521206, 4014266398, 3131182162, 2252841313, 2823678462, 1585737143, 249025536, 2214716005, 964173973, 1247819089, 3822247754, 4028631134, 1046427558, 3172929050, 2774508643, 4014335927, 3367680087, 371238079, 1185853926, 3127600616, 1916052963, 1575897628, 3451058851, 2062777055, 1790667418, 394625681, 2382373632, 1285427260, 2643027723, 3123651687, 4210562860, 2711525376, 2971180694, 250367950, 18281469, 120536218, 4192947987, 3699693593, 1520329608, 1965300243, 2511166512, 2260906473, 1471672543, 1292752813, 3342751218, 1083026259, 1028770826, 897765950, 2771274302, 301031870, 3677882617, 1770162684, 2354568845, 1185428271, 1940714535, 3200296384, 2198543582, 2522249968, 4168225877, 1136266250, 1665230132, 1009666566, 2466777420, 3654387933, 3541099283, 399564888, 2029519241, 1938918846, 1998008849, 1550075810, 736109086, 1947920262, 2929137316, 3896575536, 160018438, 3287729280, 2786425677, 1978735038, 1710922518, 3276629185, 901887228, 1409381921, 1802710052, 1533198493, 2763965225, 1964572840, 3805673305, 421729960, 877445562, 4050503427, 3604482097, 3845387322, 4278931548, 283179779, 2949352089, 2103367957, 1904833415, 4265850834, 849901850, 2106067390, 2387713572, 1562826559, 3377379712, 3765702780, 3134208395, 2229885327, 1227161476, 4213661447, 2384444653, 1754919942, 525276836, 3782509164, 3431539636, 1957659380, 214224581, 1820030205, 402854320, 1312718859, 479792015, 3253927879, 2264079477, 1411545279, 3940890503, 734882519, 2307654333, 3727447050, 1000736929, 781283495, 166924185, 2003263903, 2946367810, 3475530663, 1896950144, 2017883729, 1865489600, 3153375112, 3600934309, 2554832449, 1936038731, 2090468206, 297532247, 82220793, 2108784711, 2274988801, 2158229567, 357938497, 662696344, 444372807, 291984896, 2569486546, 2349993887, 2005339277, 2362757906, 2519176885, 711983617, 2991638223, 876592362, 3163500251, 3324574670, 3127672184, 3041229993, 2414390677, 1392258194, 2794334570, 3548296436, 3011140001, 1828253493, 2351319417, 3225288707, 1106524169, 1599161189, 3062282683, 3951516442, 1121607452, 2985198106, 4026048312, 3823199301, 3796034591, 1251148600, 527027488, 2554316720, 1932632207, 4054901843, 2744653022, 466873369, 785726271, 779650487, 1228118542, 3720366317, 933141116, 366993130, 3173964277, 2736457468, 4166518218, 1133880834, 3295525464, 2873848756, 3947853880, 2785201906, 4013307888, 4151668616, 3895421817, 4157205930, 2349920505, 3388115512, 668197780, 2306697033, 2467551547, 2452535817, 3907210798, 258859797, 1652150479, 2761544991, 348823145, 598866271, 1840339092, 989877976, 3496161556, 1220481233, 3038481586, 2902977113, 3802129318, 3029637914, 1173532510, 849696056, 507093273, 3831670887, 364865188, 1633968215, 200011283, 3143165869, 3364273874, 1348429487, 1835863290, 4200007791, 1943539278, 379243637]
states = list(map(int, states))

for offset in tqdm(range(1000)):
    random.setstate((3, tuple(states + [0]), None))
    _ = [random.getrandbits(32) for _ in range(offset)]
    r = randomdpoly(18, 18)
    pt = balancedmod(ct_flag - convolution(pk, r), q)
    coeffs = pt.list()
    if all([i in [-1, 0, 1] for i in coeffs]):
        FLAG = long_to_bytes(decode(pt))
        if FLAG.startswith(b"hitcon{"):
            print(FLAG)
            break

# hitcon{ohno!secure_random_is_50_important!}