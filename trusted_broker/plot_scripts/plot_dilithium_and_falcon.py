import matplotlib.pyplot as plt
import numpy as np

# Data for Dilithium
dilithium_versions = ['Dilithium2', 'Dilithium3', 'Dilithium5']
dilithium_keygen = [498, 881, 1426]
dilithium_sign = [1583, 2641, 3261]
dilithium_verify = [491, 808, 1374]

# Data for Falcon-EMU
falcon_emu_versions = ['Falcon-512-EMU', 'Falcon-1024-EMU']
falcon_emu_keygen = [50563, 141149]
falcon_emu_sign = [13903, 30479]
falcon_emu_verify = [109, 235]

# Data for Falcon-FPU
falcon_fpu_versions = ['Falcon-512-FPU', 'Falcon-1024-FPU']
falcon_native_keygen = [25829, 65429]
falcon_native_sign = [1084, 2204]
falcon_native_verify = [114, 236]

# Plotting keygen data
fig, ax1 = plt.subplots()
bar_width = 0.4
index = np.arange(len(dilithium_versions) + len(falcon_emu_versions) + len(falcon_fpu_versions))
print(index)

'''
plt.bar(index, dilithium_keygen + falcon_emu_keygen + falcon_native_keygen, bar_width, label='KeyGen', color='tab:cyan')
# Rotate x-axis labels
plt.xticks(rotation=25, ha='right')  # 'rotation' specifies the rotation angle, 'ha' is the horizontal alignment
plt.subplots_adjust(bottom=0.2)  # Adjust the bottom parameter as needed
#plt.xlabel('Post-Quantum digital signature schemes')
plt.xticks(fontsize=10)
plt.ylabel('Logarithmic time (μs)')
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.title('Key generation for Dilithium, Falcon-EMU, and Falcon-FPU')
plt.xticks(index, dilithium_versions + falcon_emu_versions + falcon_fpu_versions)
#plt.legend()'''

# Plotting sign and verify data
fig, ax2 = plt.subplots()
bar_width = 0.25
index = np.arange(len(dilithium_versions) + len(falcon_emu_versions) + len(falcon_fpu_versions))

plt.bar(index, dilithium_keygen + falcon_emu_keygen + falcon_native_keygen, bar_width, label='KeyGen', color='tab:green',edgecolor='grey')
# Plot sign data
plt.bar(index+bar_width, dilithium_sign + falcon_emu_sign + falcon_native_sign, bar_width, label='Sign', color='navy', edgecolor='grey')

# Plot verify data on top of sign data
#plt.bar(index, dilithium_verify + falcon_emu_verify + falcon_native_verify, bar_width, label='Verify', color='lightcoral', bottom=dilithium_sign + falcon_emu_sign + falcon_native_sign)
plt.bar(index+bar_width*2, dilithium_verify + falcon_emu_verify + falcon_native_verify, bar_width, label='Verify', color='lightcoral', edgecolor='grey')

# Adjust the bottom margin
plt.subplots_adjust(bottom=0.2)

#plt.xlabel('Post-Quantum digital signature schemes')
plt.xticks(rotation=25, ha="right")
plt.xticks(index+bar_width, dilithium_versions + falcon_emu_versions + falcon_fpu_versions)
plt.ylabel('Logarithmic time (μs)')
plt.yscale('log')
#plt.ylim(bottom=1000)
plt.title('KeyGen, sign and verify times for Dilithium and Falcon')
plt.legend()
plt.tight_layout()

plt.show()