#ifndef _MQTT_THIRD_PARTY_SYS_CONFIG_H_
#define _MQTT_THIRD_PARTY_SYS_CONFIG_H_

// TODO: write string for generating this included files for different system ports
#define    MP_MALLOC(size)                    malloc(size)            ////  pvPortMalloc(size)           
#define    MP_REALLOC(mem, oldsize, newsize)  realloc(mem, newsize)   ////  pvPortRealloc(mem, newsize)  
#define    MP_CALLOC(nmemb, size)             calloc(nmemb, size)     ////  pvPortCalloc(nmemb, size)    
#define    MP_FREE(mem, size)                 free(mem)               ////  vPortFree(mem)                 


// ---- for libtomcrypto
// TODO: write string for generating the parameters below for different system ports
#define  XMALLOC   malloc     //// pvPortMalloc   
#define  XFREE     free       //// vPortFree      
#define  XREALLOC  realloc    //// pvPortRealloc  
#define  XCALLOC   calloc     //// pvPortCalloc   

#endif // end of _MQTT_THIRD_PARTY_SYS_CONFIG_H_
