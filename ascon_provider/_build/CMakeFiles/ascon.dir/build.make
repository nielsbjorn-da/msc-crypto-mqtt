# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/niels/Documents/msc-crypto-mqtt/ascon_provider

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build

# Include any dependencies generated for this target.
include CMakeFiles/ascon.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/ascon.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/ascon.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ascon.dir/flags.make

../a_params.c: ../libprov/perl/gen_param_LL.pl
../a_params.c: ../ascon_params.dat
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating ../a_params.c, ../a_params.h"
	perl /home/niels/Documents/msc-crypto-mqtt/ascon_provider/libprov/perl/gen_param_LL.pl /home/niels/Documents/msc-crypto-mqtt/ascon_provider/a_params.c /home/niels/Documents/msc-crypto-mqtt/ascon_provider/a_params.h /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon_params.dat

../a_params.h: ../a_params.c
	@$(CMAKE_COMMAND) -E touch_nocreate ../a_params.h

CMakeFiles/ascon.dir/ascon.c.o: CMakeFiles/ascon.dir/flags.make
CMakeFiles/ascon.dir/ascon.c.o: ../ascon.c
CMakeFiles/ascon.dir/ascon.c.o: CMakeFiles/ascon.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/ascon.dir/ascon.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/ascon.dir/ascon.c.o -MF CMakeFiles/ascon.dir/ascon.c.o.d -o CMakeFiles/ascon.dir/ascon.c.o -c /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon.c

CMakeFiles/ascon.dir/ascon.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ascon.dir/ascon.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon.c > CMakeFiles/ascon.dir/ascon.c.i

CMakeFiles/ascon.dir/ascon.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ascon.dir/ascon.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon.c -o CMakeFiles/ascon.dir/ascon.c.s

CMakeFiles/ascon.dir/a_params.c.o: CMakeFiles/ascon.dir/flags.make
CMakeFiles/ascon.dir/a_params.c.o: ../a_params.c
CMakeFiles/ascon.dir/a_params.c.o: CMakeFiles/ascon.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/ascon.dir/a_params.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/ascon.dir/a_params.c.o -MF CMakeFiles/ascon.dir/a_params.c.o.d -o CMakeFiles/ascon.dir/a_params.c.o -c /home/niels/Documents/msc-crypto-mqtt/ascon_provider/a_params.c

CMakeFiles/ascon.dir/a_params.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ascon.dir/a_params.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/niels/Documents/msc-crypto-mqtt/ascon_provider/a_params.c > CMakeFiles/ascon.dir/a_params.c.i

CMakeFiles/ascon.dir/a_params.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ascon.dir/a_params.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/niels/Documents/msc-crypto-mqtt/ascon_provider/a_params.c -o CMakeFiles/ascon.dir/a_params.c.s

CMakeFiles/ascon.dir/ascon80pq/printstate.c.o: CMakeFiles/ascon.dir/flags.make
CMakeFiles/ascon.dir/ascon80pq/printstate.c.o: ../ascon80pq/printstate.c
CMakeFiles/ascon.dir/ascon80pq/printstate.c.o: CMakeFiles/ascon.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/ascon.dir/ascon80pq/printstate.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/ascon.dir/ascon80pq/printstate.c.o -MF CMakeFiles/ascon.dir/ascon80pq/printstate.c.o.d -o CMakeFiles/ascon.dir/ascon80pq/printstate.c.o -c /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon80pq/printstate.c

CMakeFiles/ascon.dir/ascon80pq/printstate.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ascon.dir/ascon80pq/printstate.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon80pq/printstate.c > CMakeFiles/ascon.dir/ascon80pq/printstate.c.i

CMakeFiles/ascon.dir/ascon80pq/printstate.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ascon.dir/ascon80pq/printstate.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon80pq/printstate.c -o CMakeFiles/ascon.dir/ascon80pq/printstate.c.s

CMakeFiles/ascon.dir/ascon128/printstate.c.o: CMakeFiles/ascon.dir/flags.make
CMakeFiles/ascon.dir/ascon128/printstate.c.o: ../ascon128/printstate.c
CMakeFiles/ascon.dir/ascon128/printstate.c.o: CMakeFiles/ascon.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/ascon.dir/ascon128/printstate.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/ascon.dir/ascon128/printstate.c.o -MF CMakeFiles/ascon.dir/ascon128/printstate.c.o.d -o CMakeFiles/ascon.dir/ascon128/printstate.c.o -c /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon128/printstate.c

CMakeFiles/ascon.dir/ascon128/printstate.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ascon.dir/ascon128/printstate.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon128/printstate.c > CMakeFiles/ascon.dir/ascon128/printstate.c.i

CMakeFiles/ascon.dir/ascon128/printstate.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ascon.dir/ascon128/printstate.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon128/printstate.c -o CMakeFiles/ascon.dir/ascon128/printstate.c.s

CMakeFiles/ascon.dir/ascon128a/printstate.c.o: CMakeFiles/ascon.dir/flags.make
CMakeFiles/ascon.dir/ascon128a/printstate.c.o: ../ascon128a/printstate.c
CMakeFiles/ascon.dir/ascon128a/printstate.c.o: CMakeFiles/ascon.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/ascon.dir/ascon128a/printstate.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/ascon.dir/ascon128a/printstate.c.o -MF CMakeFiles/ascon.dir/ascon128a/printstate.c.o.d -o CMakeFiles/ascon.dir/ascon128a/printstate.c.o -c /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon128a/printstate.c

CMakeFiles/ascon.dir/ascon128a/printstate.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ascon.dir/ascon128a/printstate.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon128a/printstate.c > CMakeFiles/ascon.dir/ascon128a/printstate.c.i

CMakeFiles/ascon.dir/ascon128a/printstate.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ascon.dir/ascon128a/printstate.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/niels/Documents/msc-crypto-mqtt/ascon_provider/ascon128a/printstate.c -o CMakeFiles/ascon.dir/ascon128a/printstate.c.s

# Object files for target ascon
ascon_OBJECTS = \
"CMakeFiles/ascon.dir/ascon.c.o" \
"CMakeFiles/ascon.dir/a_params.c.o" \
"CMakeFiles/ascon.dir/ascon80pq/printstate.c.o" \
"CMakeFiles/ascon.dir/ascon128/printstate.c.o" \
"CMakeFiles/ascon.dir/ascon128a/printstate.c.o"

# External object files for target ascon
ascon_EXTERNAL_OBJECTS =

ascon.so: CMakeFiles/ascon.dir/ascon.c.o
ascon.so: CMakeFiles/ascon.dir/a_params.c.o
ascon.so: CMakeFiles/ascon.dir/ascon80pq/printstate.c.o
ascon.so: CMakeFiles/ascon.dir/ascon128/printstate.c.o
ascon.so: CMakeFiles/ascon.dir/ascon128a/printstate.c.o
ascon.so: CMakeFiles/ascon.dir/build.make
ascon.so: libprov/libprov.a
ascon.so: CMakeFiles/ascon.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking C shared module ascon.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ascon.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ascon.dir/build: ascon.so
.PHONY : CMakeFiles/ascon.dir/build

CMakeFiles/ascon.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ascon.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ascon.dir/clean

CMakeFiles/ascon.dir/depend: ../a_params.c
CMakeFiles/ascon.dir/depend: ../a_params.h
	cd /home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/niels/Documents/msc-crypto-mqtt/ascon_provider /home/niels/Documents/msc-crypto-mqtt/ascon_provider /home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build /home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build /home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/CMakeFiles/ascon.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ascon.dir/depend
