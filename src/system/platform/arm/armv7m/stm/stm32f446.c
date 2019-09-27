#include "mqtt_include.h"


// Private macro -------------------------------------------------------------
#define  HAL_DMA_RECV_BUF_SIZE  0x100

// Private variables ---------------------------------------------------------
// timer used for other peripherals in STM32F446 development board
static  TIM_HandleTypeDef   htim2;
// STM32F446 board doesn't have network hardware module, in order to run this MQTT implementation,
// it's essential to connect this board to external network device (e.g. ESP8266 wifi module)
static  UART_HandleTypeDef haluart3; 
// the DMA module used with UART3 (STM32F4xx board)
static  DMA_HandleTypeDef  haldma_usart3_rx; 
// get rough response data from ESP device.
static  uint8_t   recv_data_buf[ HAL_DMA_RECV_BUF_SIZE ]; 
// in each system port, DMA/UART ISR should specify starting offset 
// and number of characters copying from network module (e.g. ESP AT software). 
static  uint16_t  dma_buf_num_char_copied = 0;
static  uint16_t  dma_buf_cpy_offset_next = 0;
static  uint16_t  dma_buf_cpy_offset_curr = 0;




// @brief  This function configures the TIM2 as a time base source. 
//         The time source is configured  to have 1ms time base with a dedicated 
//         Tick interrupt priority. 
// @note   This function is called  automatically at the beginning of program after
//         reset by HAL_Init() or at any time when clock is configured, by HAL_RCC_ClockConfig(). 
// @param  TickPriority: Tick interrupt priority.
// @retval HAL status
// 
static HAL_StatusTypeDef STM32_HAL_InitTick(uint32_t TickPriority)
{
    RCC_ClkInitTypeDef    clkconfig;
    uint32_t              uwTimclock = 0;
    uint32_t              uwPrescalerValue = 0;
    uint32_t              pFLatency;
    
    /*Configure the TIM2 IRQ priority */
    HAL_NVIC_SetPriority(TIM2_IRQn, TickPriority ,0); 
    
    /* Enable TIM2 clock */
    __HAL_RCC_TIM2_CLK_ENABLE();
    
    /* Get clock configuration */
    HAL_RCC_GetClockConfig(&clkconfig, &pFLatency);
    
    /* Compute TIM2 clock */
    uwTimclock = HAL_RCC_GetPCLK1Freq();
     
    /* Compute the prescaler value to have TIM2 counter clock equal to 1MHz */
    uwPrescalerValue = (uint32_t) ((uwTimclock / 1000000) - 1);
    
    /* Initialize TIM2 */
    htim2.Instance = TIM2;
    
    /* Initialize TIMx peripheral as follow:
    + Period = [(TIM2CLK/1000) - 1]. to have a (1/1000) s time base.
    + Prescaler = (uwTimclock/1000000 - 1) to have a 1MHz counter clock.
    + ClockDivision = 0
    + Counter direction = Up
    */
    htim2.Init.Period = (1000000 / 1000) - 1;
    htim2.Init.Prescaler = uwPrescalerValue;
    htim2.Init.ClockDivision = 0;
    htim2.Init.CounterMode = TIM_COUNTERMODE_UP;
    if(HAL_TIM_Base_Init(&htim2) == HAL_OK) {
      /* Start the TIM time Base generation in interrupt mode */
      return HAL_TIM_Base_Start_IT(&htim2);
    }
    
    /* Return function status */
    return HAL_ERROR;
} // end of STM32_HAL_InitTick



// Initializes the Global MSP.
static void STM32_HAL_MspInit(void)
{
  __HAL_RCC_SYSCFG_CLK_ENABLE();
  __HAL_RCC_PWR_CLK_ENABLE();
}




/**
  * @brief System Clock Configuration
  * @retval None
  */
static HAL_StatusTypeDef SystemClock_Config(void)
{
    HAL_StatusTypeDef status;
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  
    /**Configure the main internal regulator output voltage 
    */
    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE3);
    /**Initializes the CPU, AHB and APB busses clocks 
    */
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
    status = HAL_RCC_OscConfig(&RCC_OscInitStruct);
    if (status != HAL_OK) {  return status;  }
    /**Initializes the CPU, AHB and APB busses clocks 
    */
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                                |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
    status =  HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0);
    if (status != HAL_OK) {  return status;  }
    return HAL_OK;
} // end of SystemClock_Config




// @brief  This function is used to initialize the HAL Library; it must be the first 
//         instruction to be executed in the main program (before to call any other
//         HAL function), it performs the following:
//           Configure the Flash prefetch, instruction and Data caches.
//           Configures the SysTick to generate an interrupt each 1 millisecond,
//           which is clocked by the HSI (at this stage, the clock is not yet
//           configured and thus the system is running from the internal HSI at 16 MHz).
//           Set NVIC Group Priority to 4.
//           Calls the STM32_HAL_MspInit() callback function defined in user file 
//           "stm32f4xx_hal_msp.c" to do the global low level hardware initialization 
//            
// @note   SysTick is used as time base for the HAL_Delay() function, the application
//         need to ensure that the SysTick time base is always set to 1 millisecond
//         to have correct HAL operation.
// @retval HAL status
// 
static HAL_StatusTypeDef STM32_HAL_Init(void)
{
    // Configure Flash prefetch, Instruction cache, Data cache
    __HAL_FLASH_INSTRUCTION_CACHE_ENABLE();
    __HAL_FLASH_DATA_CACHE_ENABLE();
    __HAL_FLASH_PREFETCH_BUFFER_ENABLE();

    // Set Interrupt Group Priority 
    HAL_NVIC_SetPriorityGrouping(NVIC_PRIORITYGROUP_4);

    // Use systick as time base source and configure 1ms tick (default clock after Reset is HSI) 
    STM32_HAL_InitTick(TICK_INT_PRIORITY);

    // Init the low level hardware 
    STM32_HAL_MspInit();

    // Return function status 
    return HAL_OK;
} // end of STM32_HAL_Init



// will be called by HAL_UART_Init()
void HAL_UART_MspInit(UART_HandleTypeDef* huart)
{
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    if(huart->Instance==USART3)
    {
        __HAL_RCC_USART3_CLK_ENABLE();
        __HAL_RCC_GPIOC_CLK_ENABLE();
        __HAL_RCC_GPIOB_CLK_ENABLE();
        // USART3 GPIO Configuration    
        // PC5     ------> USART3_RX
        // PB10    ------> USART3_TX 
        GPIO_InitStruct.Pin = GPIO_PIN_5;
        GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
        GPIO_InitStruct.Pull = GPIO_PULLUP;
        GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
        GPIO_InitStruct.Alternate = GPIO_AF7_USART3;
        HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

        GPIO_InitStruct.Pin = GPIO_PIN_10;
        GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
        GPIO_InitStruct.Pull = GPIO_PULLUP;
        GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
        GPIO_InitStruct.Alternate = GPIO_AF7_USART3;
        HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);
    }
} // end of HAL_UART_MspInit


// @brief  Suspend Tick increment.
// @note   Disable the tick increment by disabling TIM2 update interrupt.
// @param  None
// @retval None
void HAL_SuspendTick(void)
{
    //  Disable TIM2 update Interrupt 
    __HAL_TIM_DISABLE_IT(&htim2, TIM_IT_UPDATE);                                                  
}


// @brief  Resume Tick increment.
// @note   Enable the tick increment by Enabling TIM2 update interrupt.
// @param  None
// @retval None
void HAL_ResumeTick(void)
{
    /* Enable TIM2 Update interrupt */
    __HAL_TIM_ENABLE_IT(&htim2, TIM_IT_UPDATE);
}



// brief This function handles Non maskable interrupt.
void NMI_Handler(void)
{
} // end of NMI_Handler



// brief This function handles Pre-fetch fault, memory access fault.
void BusFault_Handler(void)
{
  while (1);
}



// brief This function handles Undefined instruction or illegal state.
void UsageFault_Handler(void)
{
  while (1);
}


// brief This function handles Debug monitor.
void DebugMon_Handler(void)
{
}


// brief This function handles TIM2 global interrupt.
void TIM2_IRQHandler(void)
{
    HAL_TIM_IRQHandler(&htim2);
}


// DMA interrupt service routine used on STM32 board
void DMA1_Stream1_IRQHandler(void)
{
  HAL_DMA_IRQHandler( &haldma_usart3_rx );
} // end of DMA1_Stream1_IRQHandler



void HAL_UART_RxHalfCpltCallback(UART_HandleTypeDef *huart)
{
} // end of HAL_UART_RxHalfCpltCallback



// executed by DMA Transmission completion (TC) event interrupt
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
    if( huart == &haluart3){
        dma_buf_num_char_copied  = HAL_DMA_RECV_BUF_SIZE  -  dma_buf_cpy_offset_curr;
        mqttSysPktRecvHandler( (huart->pRxBuffPtr + dma_buf_cpy_offset_curr), dma_buf_num_char_copied );
        dma_buf_cpy_offset_curr = 0;
    }
} // end of HAL_UART_RxCpltCallback



// UART Rx interrupt service routine in this test
void USART3_IRQHandler( void )
{
    HAL_UART_IRQHandler(&haluart3);
    // check if Idle flag is set, if idle line detection event leads to this interrupt.
    if ( __HAL_UART_GET_FLAG( &haluart3, UART_FLAG_IDLE ) )
    {
        // clear current IDLE-detection interrupt.
        __HAL_UART_CLEAR_IDLEFLAG( &haluart3 );
        // calculate received data bytes & its length, and pass it to higher-level handling function.
        dma_buf_cpy_offset_next = HAL_DMA_RECV_BUF_SIZE - __HAL_DMA_GET_COUNTER( &haldma_usart3_rx ); 
        dma_buf_num_char_copied  = dma_buf_cpy_offset_next -  dma_buf_cpy_offset_curr;
        mqttSysPktRecvHandler( (haluart3.pRxBuffPtr + dma_buf_cpy_offset_curr), dma_buf_num_char_copied );
        dma_buf_cpy_offset_curr = dma_buf_cpy_offset_next;
    } 
} // end of USART3_IRQHandler








static HAL_StatusTypeDef  STM32_HAL_periph_Init( void )
{
    // enable DMA 1 Stream 1 for UART3 Rx
    __HAL_RCC_DMA1_CLK_ENABLE();
    HAL_NVIC_SetPriority( DMA1_Stream1_IRQn, (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY + 1), 0 );
    HAL_NVIC_EnableIRQ( DMA1_Stream1_IRQn );
    //  ---------- initialize UART for ESP device ---------- 
    haluart3.Instance = USART3;
    haluart3.Init.BaudRate = 115200;
    haluart3.Init.WordLength = UART_WORDLENGTH_8B;
    haluart3.Init.StopBits = UART_STOPBITS_1;
    haluart3.Init.Parity = UART_PARITY_NONE;
    haluart3.Init.Mode = UART_MODE_TX_RX;
    haluart3.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    haluart3.Init.OverSampling = UART_OVERSAMPLING_16;
    if (HAL_UART_Init(&haluart3) != HAL_OK) {
        return HAL_ERROR;
    }
    //// manually enable IDLE line detection interrupt
    __HAL_UART_ENABLE_IT( &haluart3 , UART_IT_IDLE );    
    HAL_NVIC_SetPriority( USART3_IRQn, (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY + 1), 0 );
    HAL_NVIC_EnableIRQ( USART3_IRQn );
    //  ---------- initialize DMA for Rx of ESP device. ---------- 
    haldma_usart3_rx.Instance = DMA1_Stream1;
    haldma_usart3_rx.Init.Channel = DMA_CHANNEL_4;
    haldma_usart3_rx.Init.Direction = DMA_PERIPH_TO_MEMORY;
    haldma_usart3_rx.Init.PeriphInc = DMA_PINC_DISABLE;
    haldma_usart3_rx.Init.MemInc = DMA_MINC_ENABLE;
    haldma_usart3_rx.Init.PeriphDataAlignment = DMA_PDATAALIGN_BYTE;
    haldma_usart3_rx.Init.MemDataAlignment = DMA_MDATAALIGN_BYTE;
    haldma_usart3_rx.Init.Mode = DMA_CIRCULAR;
    haldma_usart3_rx.Init.Priority = DMA_PRIORITY_LOW;
    haldma_usart3_rx.Init.FIFOMode = DMA_FIFOMODE_DISABLE;
    if (HAL_DMA_Init(&haldma_usart3_rx) != HAL_OK) {
        return HAL_ERROR ;
    }
    __HAL_LINKDMA(&haluart3, hdmarx, haldma_usart3_rx);
    //  ---------- initialize GPIO pins  for ESP device ---------- 
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    // GPIO Ports Clock Enable 
    __HAL_RCC_GPIOB_CLK_ENABLE();
    // Configure GPIO pin Output Level
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_9 | GPIO_PIN_4, GPIO_PIN_RESET);
    // Configure GPIO pins : PB10 PB4 
    GPIO_InitStruct.Pin = GPIO_PIN_9 | GPIO_PIN_4;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);
    return HAL_OK;
} // end of STM32_HAL_periph_Init 



mqttRespStatus   mqttPlatformPktRecvEnable( void )
{
    mqttRespStatus     response   = MQTT_RESP_OK;
    HAL_StatusTypeDef  status_chk = HAL_ERROR;
    dma_buf_num_char_copied  = 0;
    dma_buf_cpy_offset_next  = 0;
    dma_buf_cpy_offset_curr  = 0;
    status_chk = HAL_UART_Receive_DMA( &haluart3, (uint8_t *)&recv_data_buf[0], HAL_DMA_RECV_BUF_SIZE );
    switch(status_chk) {
        case HAL_OK       : response = MQTT_RESP_OK     ;   break; 
        case HAL_ERROR    : response = MQTT_RESP_ERR    ;   break; 
        case HAL_BUSY     : response = MQTT_RESP_BUSY   ;   break; 
        case HAL_TIMEOUT  : response = MQTT_RESP_TIMEOUT;   break; 
        default           : response = MQTT_RESP_ERR    ;   break;
    }
    return response;
} // end of mqttPlatformPktRecvEnable 



mqttRespStatus   mqttPlatformPktRecvDisable( void )
{
    mqttRespStatus     response   = MQTT_RESP_OK;
    HAL_StatusTypeDef  status_chk = HAL_ERROR;
    status_chk = HAL_UART_DMAStop( &haluart3 );
    ESP_MEMSET( (void *)&recv_data_buf, 0x00, HAL_DMA_RECV_BUF_SIZE );
    switch(status_chk) {
        case HAL_OK       : response = MQTT_RESP_OK     ;   break; 
        case HAL_ERROR    : response = MQTT_RESP_ERR    ;   break; 
        case HAL_BUSY     : response = MQTT_RESP_BUSY   ;   break; 
        case HAL_TIMEOUT  : response = MQTT_RESP_TIMEOUT;   break; 
        default           : response = MQTT_RESP_ERR    ;   break;
    }
    return response;
} // end of mqttPlatformPktRecvDisable 



mqttRespStatus  mqttPlatformPktSend( void* data, size_t len, uint32_t timeout )
{
    mqttRespStatus     response   = MQTT_RESP_OK;
    HAL_StatusTypeDef  status_chk = HAL_ERROR;
    status_chk  = HAL_UART_Transmit( &haluart3, (uint8_t* )data, len, timeout );
    switch(status_chk) {
        case HAL_OK       : response = MQTT_RESP_OK     ;   break; 
        case HAL_ERROR    : response = MQTT_RESP_ERR    ;   break; 
        case HAL_BUSY     : response = MQTT_RESP_BUSY   ;   break; 
        case HAL_TIMEOUT  : response = MQTT_RESP_TIMEOUT;   break; 
        default           : response = MQTT_RESP_ERR    ;   break;
    }
    return response;
} // end of mqttPlatformPktSend



mqttRespStatus  mqttPlatformNetworkModRst( uint8_t state )
{
    // at here, state = 0 means reset assertion, non-zero value means reset de-assertion.
    GPIO_PinState pinstate = state==0x0 ? GPIO_PIN_RESET: GPIO_PIN_SET;
    HAL_GPIO_WritePin( GPIOB, GPIO_PIN_4, pinstate );
    return  MQTT_RESP_OK;
} // end of mqttPlatformNetworkModRst





word32  mqttPlatformRNG( word32 maxnum )
{
    word32 out = 0;
    return out;
} // end of mqttUtilPRNG




mqttRespStatus  mqttPlatformInit( void )
{
    HAL_StatusTypeDef  status;
    // MCU Configuration--------------------------------------------------------  
    // Reset of all peripherals, Initializes the Flash interface and the Systick. 
    STM32_HAL_Init();
    // Configure the system clock 
    status = SystemClock_Config();
    // Configure peripherals that will be used in this MQTT implementation
    if(status == HAL_OK) {
        status = STM32_HAL_periph_Init();
    }
    return  (status == HAL_OK ? MQTT_RESP_OK : MQTT_RESP_ERR );
} // end of mqttPlatformInit




mqttRespStatus  mqttPlatformDeInit( void )
{ // dummy , don't do anythin
    return   MQTT_RESP_OK ;
} // end of mqttHwPlatformDeInit



