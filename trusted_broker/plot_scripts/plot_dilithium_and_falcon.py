import matplotlib.pyplot as plt
import numpy as np

# Data for Dilithium
dilithium_versions = ['Dilithium2', 'Dilithium3', 'Dilithium5']
dilithium_keygen = [498, 881, 1426]
dilithium_sign = [1583, 2641, 3261]
dilithium_verify = [491, 808, 1374]

# Data for Falcon-EMU
falcon_emu_versions = ['Falcon_EMU-512', 'Falcon_EMU-1024']
falcon_emu_keygen = [50563, 141149]
falcon_emu_sign = [13903, 30479]
falcon_emu_verify = [109, 235]

# Data for Falcon-FPU
falcon_fpu_versions = ['Falcon_FPU-512', 'Falcon_FPU-1024']
falcon_native_keygen = [25829, 65429]
falcon_native_sign = [1084, 2204]
falcon_native_verify = [114, 236]

# Plotting keygen data
fig, ax1 = plt.subplots()
bar_width = 0.4
index = np.arange(len(dilithium_versions) + len(falcon_emu_versions) + len(falcon_fpu_versions))
print(index)


plt.bar(index, dilithium_keygen + falcon_emu_keygen + falcon_native_keygen, bar_width, label='KeyGen', color='tab:cyan')
# Rotate x-axis labels
plt.xticks(rotation=25, ha='right')  # 'rotation' specifies the rotation angle, 'ha' is the horizontal alignment
plt.subplots_adjust(bottom=0.2)  # Adjust the bottom parameter as needed
plt.xlabel('Post-Quantum digital signature schemes')
plt.xticks(fontsize=10)
plt.ylabel('Keygen Time log\u2081\u2080(micro seconds)')
plt.yscale('log')  # Set y-axis to logarithmic scale
plt.title('Key generation for Dilithium, Falcon-EMU, and Falcon-FPU')
plt.xticks(index, dilithium_versions + falcon_emu_versions + falcon_fpu_versions)
plt.legend()

# Plotting sign and verify data
fig, ax2 = plt.subplots()
bar_width = 0.4
index = np.arange(len(dilithium_versions) + len(falcon_emu_versions) + len(falcon_fpu_versions))

# Plot sign data
plt.bar(index, dilithium_sign + falcon_emu_sign + falcon_native_sign, bar_width, label='Sign', color='navy')

# Plot verify data on top of sign data
plt.bar(index, dilithium_verify + falcon_emu_verify + falcon_native_verify, bar_width, label='Verify', color='lightcoral', bottom=dilithium_sign + falcon_emu_sign + falcon_native_sign)

# Adjust the bottom margin
plt.subplots_adjust(bottom=0.2)

plt.xlabel('Post-Quantum digital signature schemes')
plt.xticks(rotation=25, ha='right')
plt.xticks(index, dilithium_versions + falcon_emu_versions + falcon_fpu_versions)
plt.ylabel('Time Sign and verify log₁₀(micro seconds)')
plt.yscale('log')
plt.ylim(bottom=1000)
plt.title('Sign and Verif for Dilithium, Falcon-EMU, and Falcon-FPU')
plt.legend()

plt.show()