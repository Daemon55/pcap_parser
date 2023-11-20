#include <iostream>
#include <string>
#include <sys/stat.h>
#include "pcap.h"

namespace fs = std::filesystem;

inline bool exists(const char* filename) {
  struct stat buffer;   
  return (stat (filename, &buffer) == 0); 
}

int main(int argc, char** argv)
{
	if(argc < 2) {
		std::cout << "Please add path to find pcap-files" << std::endl;
		return 0;
	}	
	if ( exists(argv[1]) == false ) {
		std::cout << "The path " << argv[1] << " is wrong, please check it" << std::endl;	
		return 0;	
	}
	auto path = argv[1];
	if (!fs::is_directory(path)){
		std::cout << "Path is not a directory" << std::endl;		
	} else {
		try {
			for (const auto & entry : fs::directory_iterator(path)) {
				CPcap c_pcap;
				c_pcap.ParseFile(entry.path());		
			}
		} catch(...) {
			std::cout << "Some errors" << std::endl;			
		}		
	}	
	return 0;
}

