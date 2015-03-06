# wireshark-hwgen
Fork of wireshark-tools (editcap), version 1.99.2 with additional support for new formats such as hwgen, a personal definition

##How to install it?

If you want to compile this project, you just have to:

1) cd path_to_the_git_folder/wireshark-hwgen

2) mkdir build; cd build

3) cmake ../src

4) make -j2 editcap


Enjoy the program! You can run it from the same terminal (./run/editcap) or install it in the base system (sudo make install).

###Problems with dependencies.
If you are suffering some inconveniences with the wireshark dependencies while compiling the program, you might want to checkout for the stable branch. You can adquire it by typing:

git clone -b wireshark-stable https://github.com/jfzazo/wireshark-hwgen.git

and you should repeat the previous steps.

##How to use it?
If you want to convert from a generic format (like pcap) to the HW generator specific type,

./run/editcap  -F hw_gen file_supported_by_editcap output_in_hw_format


To make the analogous operation in the reverse direction:

./run/editcap  -F libpcap input_in_hw_format output_supported_by_libpcap 

Just the libpcap has been adapted to processed the hw_gen captured style. Sorry for the inconveniences.

