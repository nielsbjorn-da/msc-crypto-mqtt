import re
import numpy as np
import matplotlib.pyplot as plt
import sys

all_sig_algs = ["dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024", "p256_dilithium2", 
                "p256_falcon512", "p384_dilithium3", "p521_dilithium5", "p521_falcon1024", "rsa3072_dilithium2", 
                "rsa3072_falcon512", "p256","p384", "p521", "rsa2048", "rsa3072"]
all_kems = ["kyber512", "p256_kyber512", "x25519_kyber512", "kyber768", "p384_kyber768", "x448_kyber768", "x25519_kyber768",
            "p256_kyber768", "kyber1024", "p521_kyber1024", "secp256r1", "secp384r1", "secp521r1", "x25519", "x448"]

sigs_low = ["rsa3072", "p256", "dilithium2", "falcon512", "rsa3072_dilithium2", "rsa3072_falcon512", "p256_dilithium2", "p256_falcon512"]
kems_low = ["secp256r1", "x25519", "kyber512", "p256_kyber512", "x25519_kyber512"]
#sigs_low = ["rsa7680", "p384", "dilithium3", "p384_dilithium3"]
#kems_low = ["secp384r1", "x448","kyber768", "p384_kyber768", "x448_kyber768", ]
#sigs_low = ["p521", "dilithium5", "falcon1024", "p521_dilithium5","p521_falcon1024"]
#kems_low = ["secp521r1", "kyber1024", "p521_kyber1024"]
# uncomment one of these to choose security level

correct_names = {"dilithium2":"Dilithium2", "dilithium3":"Dilithium3", "dilithium5":"Dilithium5", "falcon512":"Falcon-512",
                  "falcon1024":"Falcon-1024", "p256_dilithium2":"P-256_Dilithium2", "p256_falcon512":"P-256_Falcon-512",
                    "p384_dilithium3":"P-384_Dilithium3", "p521_dilithium5":"P-521_Dilithium5", "p521_falcon1024":"P-521_Falcon-1024",
                      "rsa3072_dilithium2":"RSA-3072_Dilithium2", "rsa3072_falcon512":"RSA-3072_Falcon-512", "p256":"P-256",
                      "p384":"P-384", "p521":"P-521", "rsa3072":"RSA-3072",
                "kyber512":"Kyber512", "p256_kyber512":"P-256_Kyber512", "x25519_kyber512":"X25519_Kyber512", 
                "kyber768":"Kyber768", "p384_kyber768":"P-384_Kyber768", "x448_kyber768":"X448_Kyber768", 
                "x25519_kyber768":"X25519_Kyber768","p256_kyber768":"P-256_Kyber768", "kyber1024":"Kyber1024", 
                "p521_kyber1024":"P-521_Kyber1024", "secp256r1":"P-256", "secp384r1":"P-384", "secp521r1":"P-521", 
                "x25519":"X25519", "x448":"X448", "rsa7680":"RSA-7680"}

all_sig_algs= sigs_low
all_kems = kems_low
data_path = 'lan_data/lenovo_handshake_test/'

kem_data_for_each_sig = {}
for alg in all_sig_algs:
        
    sig_alg = alg #sys.argv[1] #all_sig_algs[1]
    #dilithium2 er anderledes i data fil
    sig_alg_data_path = data_path + sig_alg + ".txt"
    kem_data_for_sig_alg = {}
    # Open the file in read mode
    with open(sig_alg_data_path, 'r') as file:
        # Iterate through each line in the file
        current_kem = ""
        current_kem_data = []
        all_lines = file.readlines()
        for i in range(len(all_lines)):
            current_line = all_lines[i]
            if current_line.startswith('Groups = '):
                current_kem = current_line.split()[2].lower()
                if current_kem not in kem_data_for_sig_alg:
                    kem_data_for_sig_alg[current_kem] = []

                next_line = all_lines[i+1]
                if next_line.startswith("Connect"):
                    
                    microsecond_time = int(next_line.split()[2])
                    
                    kem_data_for_sig_alg[current_kem].append(microsecond_time)

        '''for line in file:
            # Check if the line starts with "Groups = "

            if line.startswith('Groups = '):

                if len(current_kem_data) > 0:
                    kem_data_for_sig_alg[current_kem.lower()] = np.array(current_kem_data)
                current_kem = line.split()[2]
                #print("Current kem:", current_kem, sig_alg)
                # If it does, print the line or do whatever you want with it
                current_kem_data = []
            elif line.startswith("Connect"):
                #print(line)
                microsecond_time = line.split()[2]
                current_kem_data.append(int(microsecond_time))
        kem_data_for_sig_alg[current_kem.lower()] = current_kem_data'''
    #print(kem_data_for_sig_alg.keys())
    kem_data_for_each_sig[sig_alg.lower()] = kem_data_for_sig_alg
    '''medians = {key: np.median(value)/1000.0 for key, value in kem_data_for_sig_alg.items()}

    plt.bar(medians.keys(), medians.values())
    plt.xticks(rotation="vertical")
    plt.subplots_adjust(bottom=0.3)
    plt.xlabel('Key-exchange algorithm')
    plt.ylabel('Time (ms)')
    plt.title(sig_alg + ' TLS MQTT connect median times')
    plt.savefig(sig_alg + ".png")
    plt.clf()'''
print(kem_data_for_each_sig)

sig_data_for_each_kem = {}
for kem in kems_low:
    sig_data_for_this_kem = {}
    for sig in sigs_low:
        kem_times = kem_data_for_each_sig[sig]
        #print("SIG:", sig)
        #print("keys", kem_times.keys())
        sig_data_for_this_kem[sig] = np.median(kem_times[kem]) / 1000

    
    sig_data_for_each_kem[kem] = sig_data_for_this_kem
print()
#print(sig_data_for_each_kem)


data = sig_data_for_each_kem[kems_low[0]]
values_to_plot = {}
# Iterate through outer keys
for outer_key, inner_dict in sig_data_for_each_kem.items():
    # Iterate through inner keys and values
    for inner_key, value in inner_dict.items():
        # If inner_key is not in values_to_plot, create a list with the current value
        if inner_key not in values_to_plot:
            values_to_plot[inner_key] = [value]
        else:
            # Append the current value to the existing list
            values_to_plot[inner_key].append(value)

# Now values_to_plot contains the desired format
print(values_to_plot)

step_size = 0.5 # low sec, high sec
#step_size = 0.3
x = np.arange(0, len(kems_low)*step_size, step_size)  # the label locations

print(x)
width = 0.05  # the width of the bars
multiplier = 0
space = 0

fig, ax = plt.subplots(layout="constrained")
cmap = plt.get_cmap('Set1') # high sec remember that ras not in pic, color should be +1

print(values_to_plot.items())
print("draw")
for attribute, measurement in values_to_plot.items():
    offset = width * multiplier
    print("location:", x + offset)
    c = cmap(multiplier)
    rects = ax.bar(x + offset, measurement, width, label=correct_names[attribute], color=c, edgecolor="grey", zorder=3)
    #ax.bar_label(rects, labels=[attribute for _ in range(len(kems_low))], padding=3)
    multiplier += 1

ax.yaxis.grid(True, which='major', color='gray', alpha=0.5)
# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Time (ms)')
ax.set_title('MQTT TLS connection times')
ax.set_xticks(x+width*len(all_sig_algs) / 2-width/2)
ax.set_xticklabels([correct_names[name] for name in kems_low])
ax.set_xlabel("Key exchange")
ax.legend(loc='upper right', ncols=len(all_sig_algs)/2, title='Digital signature')
#ax.legend(loc='upper right', ncols=len(all_sig_algs)/2, title='Digital signature')
ax.set_ylim(0, 160)
plt.show()