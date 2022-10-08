

//#define USE_ARIA 
//#define USE_CAMELLIA 
//#define USE_GOST 
//#define USE_HIGHT 
//#define USE_IDEA 
//#define USE_NOEKEON 
//#define USE_PRESENT 
//#define USE_SEED 
//#define USE_SIMON 
#define USE_SPECK 




/*
Key sizes available:

Aria 128/192/256
Camellia 128/192/256
Gost 256
Hight 128
Idea 128
Noekeon 128
Present 80/128
Seed 128
Simon 128/192/256
Speck 128/192/256

*/
#define KEYSIZE 256

#ifdef USE_ARIA
	#define TEXT_SIZE 4
#endif

#ifdef USE_CAMELLIA
	#define TEXT_SIZE 4
#endif

#ifdef USE_NOEKEON
	#define TEXT_SIZE 4
#endif

#ifdef USE_SEED
	#define TEXT_SIZE 4
#endif

#ifdef USE_SIMON
	#define TEXT_SIZE 4
#endif

#ifdef USE_SPECK
	#define TEXT_SIZE 4
#endif

#ifdef USE_IDEA
	#define TEXT_SIZE 2
#endif

#ifdef USE_PRESENT
	#define TEXT_SIZE 2
#endif

#ifdef USE_HIGHT
	#define TEXT_SIZE 2
#endif

#ifdef USE_GOST
	#define TEXT_SIZE 2
#endif




