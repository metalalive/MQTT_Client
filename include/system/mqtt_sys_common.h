#ifndef MQTT_SYS_COMMON_H
#define MQTT_SYS_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif


// if we don't have specific implementation for following functions, then we
// call functions from standard C library as default
#ifndef  XMEMSET
#define  XMEMSET  memset
#endif 

#ifndef  XMALLOC
#define  XMALLOC  malloc
#endif 

#ifndef  XMEMCPY
#define  XMEMCPY  memcpy
#endif 

#ifndef  XMEMFREE 
#define  XMEMFREE  free
#endif 

#ifndef  XSTRLEN 
#define  XSTRLEN  strlen
#endif 

#ifndef  XSTRCHR
#define  XSTRCHR  strchr
#endif

#ifndef  XMEMCHR
#define  XMEMCHR  memchr
#endif

#ifndef  XSTRSTR
#define  XSTRSTR  strstr
#endif

#ifndef  XSTRNSTR
#define  XSTRNSTR  strnstr
#endif

#ifndef  XSTRNCMP
#define  XSTRNCMP  strncmp
#endif

#ifndef  XASSERT
#define  XASSERT( x ) if((x) == 0) { for(;;); } 
#endif



// ----------------------------------------------------------------------------------
// low-level interfaces for implementation on different operating system / platform
// ----------------------------------------------------------------------------------

mqttRespStatus  mqttSysInit( void );

mqttRespStatus  mqttSysDeInit( void );

mqttRespStatus  mqttSysThreadCreate( const char* name, mqttSysThreFn thread_fn,  void* const arg,  size_t stack_size,
                                     uint32_t prio, uint8_t isPrivileged,  mqttSysThre_t *out_thread_ptr );

mqttRespStatus  mqttSysThreadDelete( mqttSysThre_t *thre_in );

mqttRespStatus  mqttSysThreadWaitUntilExit( mqttSysThre_t *thre_in, void **return_p );

void  mqttSysDelay(uint32_t ms);


mqttRespStatus  mqttSysNetconnStart( mqttCtx_t *mctx );

mqttRespStatus  mqttSysNetconnStop( mqttCtx_t *mctx );

// Here are for packet reading / writing from underlying system implementation
// meaning of the return value :
//     positive  integer --> number of bytes read 
//     negative  integer --> error code defined in mqttRespStatus
// 
// it's unlikely to return zero value even on transmission timeout 

int  mqttSysPktRead(  mqttCtx_t *mctx, byte *buf, word32 buf_len);

int  mqttSysPktWrite( mqttCtx_t *mctx, byte *buf, word32 buf_len);


// the packet receiving handler is the interface to interrupt service routine &  is 
// supposed to be called by underlying hardware layer functions.
mqttRespStatus  mqttSysPktRecvHandler( uint8_t* data, uint16_t data_len );


// Random Number Generator (RNG), the most appropriate way to implement RNG in an embedded application 
// (especially for MCU-based project) is to setup your hardware input. For example :
//     * use analog devices that sense surrounding environment change such as lighting condition,
//       temperature, humidity, air quality etc... convert these changes to digital random bits in the CPU system.
//     * design your own RNG circuit e.g. OneRNG, to create noise, convert them into digital random bits.
//
// these can be reliable sources of random seed value.
//
// the output ranges from zero to given input maxnum
word32  mqttSysRNG( word32 maxnum );



#ifdef __cplusplus
}
#endif
#endif // end of MQTT_SYS_COMMON_H
