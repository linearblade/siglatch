#ifndef SIGLATCH_NONCE_CACHE_H
#define SIGLATCH_NONCE_CACHE_H

#include <time.h>

#define NONCE_MAX 128
#define NONCE_STRLEN 32
#define NONCE_TTL 60  // seconds

//store by value 
//const char *(*unix_string)(void);
typedef struct {
    void (*init)(void);                                // Initialize cache
    void (*shutdown)(void);                            // Optional cleanup
    int  (*check)(const char *nonce, time_t now);      // Returns 1 if seen (replay), 0 if new
    void (*add)(const char *nonce, time_t now);        // Register new nonce
    void (*clear)(void);                               // Reset cache
} NonceCache;
/*

  //store by ptr, but since start up only, its cleaner and frankly easier
typedef struct {
  void (*init)(void);                 
  void (*shutdown)(void);             
  
  int  (*check)(const char *nonce, time_t now);  // Returns 1 if seen (replay), 0 if new
  void (*add)(const char *nonce, time_t now);
  void (*clear)(void);
} NonceCache;
*/
const NonceCache *get_nonce_cache(void);

#endif // SIGLATCH_NONCE_CACHE_H
