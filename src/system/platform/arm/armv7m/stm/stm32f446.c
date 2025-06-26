#include "mqtt_include.h"

// Private macro -------------------------------------------------------------
// TODO: figure out why Rx buffer size less than 0x200 bytes could lead to packet loss
#define HAL_DMA_RECV_BUF_SIZE 0x280

// Private variables ---------------------------------------------------------
extern const byte   mqttAuthInitHour;
extern const byte   mqttAuthInitMinutes;
extern const byte   mqttAuthInitSeconds;
extern const byte   mqttAuthInitMonth;
extern const byte   mqttAuthInitDate;
extern const word16 mqttAuthInitYear;
// data structure for RTC (Real-Time Calendar), for getting date time
static RTC_HandleTypeDef hrtc;
// get rough response data from ESP device.
static uint8_t recv_data_buf[HAL_DMA_RECV_BUF_SIZE];
// in each system port, DMA/UART ISR should specify starting offset
// and number of characters copying from network module (e.g. ESP AT software).
static uint16_t dma_buf_num_char_copied = 0;
static uint16_t dma_buf_cpy_offset_next = 0;
static uint16_t dma_buf_cpy_offset_curr = 0;

static uint8_t platform_stm32_hal_init_flag = 0;

// ---- external configuration functions ----
extern HAL_StatusTypeDef   SystemClock_Config(void);
extern HAL_StatusTypeDef   STM32_HAL_GPIO_Init(void);
extern HAL_StatusTypeDef   STM32_HAL_DMA_Init(void);
extern HAL_StatusTypeDef   STM32_HAL_UART_Init(void);
extern HAL_StatusTypeDef   STM32_HAL_UART_DeInit(void);
extern UART_HandleTypeDef *STM32_config_UART(void);
extern DMA_HandleTypeDef  *STM32_config_DMA4UART(void);
extern HAL_StatusTypeDef   STM32_HAL_GeneralTimer_Init(uint32_t TickPriority);
extern TIM_HandleTypeDef  *STM32_config_GeneralTimer(void);

// Invoked by `HAL_Init()`,  Initializes the Global MSP.
// this function overwrites the one in HAL default function
void HAL_MspInit(void) {
    __HAL_RCC_SYSCFG_CLK_ENABLE();
    __HAL_RCC_PWR_CLK_ENABLE();
}

// will be called by HAL_RTC_Init
void HAL_RTC_MspInit(RTC_HandleTypeDef *hrtc) {
    if (hrtc->Instance == RTC) {
        // Peripheral clock enable
        __HAL_RCC_RTC_ENABLE();
    }
}

void STM32_generic_DMAstream_IRQHandler(DMA_HandleTypeDef *hdma) { HAL_DMA_IRQHandler(hdma); }

void HAL_UART_RxHalfCpltCallback(UART_HandleTypeDef *huart) {}

// executed by DMA Transmission completion (TC) event interrupt
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
    UART_HandleTypeDef *uart_cfg = STM32_config_UART();
    if (huart == uart_cfg) {
        dma_buf_num_char_copied = HAL_DMA_RECV_BUF_SIZE - dma_buf_cpy_offset_curr;
        mqttSysPktRecvHandler(
            (huart->pRxBuffPtr + dma_buf_cpy_offset_curr), dma_buf_num_char_copied
        );
        dma_buf_cpy_offset_curr = 0;
    }
}

// UART Rx interrupt service routine in this test
void STM32_generic_USART_IRQHandler(UART_HandleTypeDef *uart_cfg) {
    HAL_UART_IRQHandler(uart_cfg);
    // check if Idle flag is set, if idle line detection event leads to this interrupt.
    if (__HAL_UART_GET_FLAG(uart_cfg, UART_FLAG_IDLE)) {
        // clear current IDLE-detection interrupt.
        __HAL_UART_CLEAR_IDLEFLAG(uart_cfg);
        DMA_HandleTypeDef *uart3_rx = STM32_config_DMA4UART();
        // calculate received data bytes & its length, and pass it to higher-level handling
        // function.
        dma_buf_cpy_offset_next = HAL_DMA_RECV_BUF_SIZE - __HAL_DMA_GET_COUNTER(uart3_rx);
        if (dma_buf_cpy_offset_next > dma_buf_cpy_offset_curr && uart_cfg->pRxBuffPtr != NULL) {
            dma_buf_num_char_copied = dma_buf_cpy_offset_next - dma_buf_cpy_offset_curr;
            mqttSysPktRecvHandler(
                (uart_cfg->pRxBuffPtr + dma_buf_cpy_offset_curr), dma_buf_num_char_copied
            );
        } // otherwise, skip the received data from this interrupt, TODO: figure out if that's
          // hardware error ?
        dma_buf_cpy_offset_curr = dma_buf_cpy_offset_next;
    }
} // end of USART3_IRQHandler

static HAL_StatusTypeDef STM32_HAL_periph_Init(void) {
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();
    HAL_StatusTypeDef result = STM32_HAL_UART_Init();
    if (result != HAL_OK) {
        return result;
    }
    result = STM32_HAL_DMA_Init();
    if (result != HAL_OK) {
        return result;
    }
    return STM32_HAL_GPIO_Init();
}

static HAL_StatusTypeDef STM32_HAL_periph_Deinit(void) { return STM32_HAL_UART_DeInit(); }

static HAL_StatusTypeDef STM32_HAL_RTC_Init(void) { // Initialize RTC and set the Time and Date
    HAL_StatusTypeDef status = HAL_OK;
    RTC_TimeTypeDef   sTime = {0};
    RTC_DateTypeDef   sDate = {0};

    hrtc.Instance = RTC;
    hrtc.Init.HourFormat = RTC_HOURFORMAT_24;
    hrtc.Init.AsynchPrediv = 127;
    hrtc.Init.SynchPrediv = 255;
    hrtc.Init.OutPut = RTC_OUTPUT_DISABLE;
    hrtc.Init.OutPutPolarity = RTC_OUTPUT_POLARITY_HIGH;
    hrtc.Init.OutPutType = RTC_OUTPUT_TYPE_OPENDRAIN;
    status = HAL_RTC_Init(&hrtc);

    if (status != HAL_OK) {
        goto done;
    }
    sTime.Hours = mqttAuthInitHour; // feed initial date/time from host system
    sTime.Minutes = mqttAuthInitMinutes;
    sTime.Seconds = mqttAuthInitSeconds;
    sTime.DayLightSaving = RTC_DAYLIGHTSAVING_NONE;
    sTime.StoreOperation = RTC_STOREOPERATION_RESET;
    status = HAL_RTC_SetTime(&hrtc, &sTime, RTC_FORMAT_BCD);
    if (status != HAL_OK) {
        goto done;
    }

    sDate.WeekDay = RTC_WEEKDAY_TUESDAY; // this implementation doesn't check what weekday it is
                                         // today, ignore this value
    sDate.Month = mqttAuthInitMonth;     // can be from RTC_MONTH_JANUARY to RTC_MONTH_DECEMBER
    sDate.Date = mqttAuthInitDate;
    sDate.Year = mqttAuthInitYear & 0xff; // seems like UTC time format
    status = HAL_RTC_SetDate(&hrtc, &sDate, RTC_FORMAT_BCD);
done:
    return status;
} // end of STM32_HAL_RTC_Init

mqttRespStatus mqttPlatformPktRecvEnable(void) {
    mqttRespStatus      response = MQTT_RESP_OK;
    HAL_StatusTypeDef   status_chk = HAL_ERROR;
    UART_HandleTypeDef *uart_cfg = STM32_config_UART();
    dma_buf_num_char_copied = 0;
    dma_buf_cpy_offset_next = 0;
    dma_buf_cpy_offset_curr = 0;
    status_chk =
        HAL_UART_Receive_DMA(uart_cfg, (uint8_t *)&recv_data_buf[0], HAL_DMA_RECV_BUF_SIZE);
    switch (status_chk) {
    case HAL_OK:
        response = MQTT_RESP_OK;
        break;
    case HAL_ERROR:
        response = MQTT_RESP_ERR;
        break;
    case HAL_BUSY:
        response = MQTT_RESP_BUSY;
        break;
    case HAL_TIMEOUT:
        response = MQTT_RESP_TIMEOUT;
        break;
    default:
        response = MQTT_RESP_ERR;
        break;
    }
    return response;
} // end of mqttPlatformPktRecvEnable

mqttRespStatus mqttPlatformPktRecvDisable(void) {
    mqttRespStatus      response = MQTT_RESP_OK;
    HAL_StatusTypeDef   status_chk = HAL_ERROR;
    UART_HandleTypeDef *uart_cfg = STM32_config_UART();
    status_chk = HAL_UART_DMAStop(uart_cfg);
    ESP_MEMSET((void *)&recv_data_buf, 0x00, HAL_DMA_RECV_BUF_SIZE);
    switch (status_chk) {
    case HAL_OK:
        response = MQTT_RESP_OK;
        break;
    case HAL_ERROR:
        response = MQTT_RESP_ERR;
        break;
    case HAL_BUSY:
        response = MQTT_RESP_BUSY;
        break;
    case HAL_TIMEOUT:
        response = MQTT_RESP_TIMEOUT;
        break;
    default:
        response = MQTT_RESP_ERR;
        break;
    }
    return response;
} // end of mqttPlatformPktRecvDisable

mqttRespStatus mqttPlatformPktSend(void *data, size_t len, uint32_t timeout) {
    mqttRespStatus      response = MQTT_RESP_OK;
    HAL_StatusTypeDef   status_chk = HAL_ERROR;
    UART_HandleTypeDef *uart_cfg = STM32_config_UART();
    status_chk = HAL_UART_Transmit(uart_cfg, (uint8_t *)data, len, timeout);
    switch (status_chk) {
    case HAL_OK:
        response = MQTT_RESP_OK;
        break;
    case HAL_ERROR:
        response = MQTT_RESP_ERR;
        break;
    case HAL_BUSY:
        response = MQTT_RESP_BUSY;
        break;
    case HAL_TIMEOUT:
        response = MQTT_RESP_TIMEOUT;
        break;
    default:
        response = MQTT_RESP_ERR;
        break;
    }
    return response;
} // end of mqttPlatformPktSend

// PB4 can be wired to reset pin (RST) of network device.
mqttRespStatus mqttPlatformNetworkModRst(uint8_t state) {
    // at here, state = 0 means reset assertion, non-zero value means reset de-assertion.
    GPIO_PinState pinstate = state == 0x0 ? GPIO_PIN_RESET : GPIO_PIN_SET;
    HAL_GPIO_WritePin(ESP8266_RST_PINGRP, ESP8266_RST_PINNUM, pinstate);
    return MQTT_RESP_OK;
} // end of mqttPlatformNetworkModRst

// the implementation generates cryptography entropy by wiring configurable pins to external
// device -- a HC-SR04 sonar sensor, the electrical noise is produced by the sensor is fed
// into embedded board to create random bit sequences, this approach is particularly useful
// for embedded systems that lack dedicated hardware Randm Number Generator (RNG).
//
// application developers should determine which pins to wire to the sonar sensor
//
// Note the sonar sensor is simply one of feasible approaches I took ,
// there are other options to implement in future (TODO)
//
mqttRespStatus mqttPlatformGetEntropy(mqttStr_t *out) {
    if ((out == NULL) || (out->data == NULL) || (out->len < 1) ||
        (out->len > MQTT_MAX_BYTES_ENTROPY)) {
        return MQTT_RESP_ERRARGS;
    }
    word32 start_time = 0, stop_time = 0;
    word32 tmp = 0, idx = 0, prev_wr_idx = 0, wr_idx = 0, wr_offset = 0;

    const word32  max_wait_time = HAL_RCC_GetPCLK1Freq() >> 5;
    GPIO_PinState echo_state;
    const uint8_t nbits_grab = 2; // grab 2 bits every time when we read from entropy
    word32        num_iterations = (out->len << 3) / nbits_grab;

    TIM_HandleTypeDef *htim = STM32_config_GeneralTimer();
    for (idx = 0; idx < num_iterations; idx++) {
        HAL_GPIO_WritePin(ENTROPY_HCSR04_OUT_GRP, ENTROPY_HCSR04_OUT_PINNUM, GPIO_PIN_SET);
        mqttSysDelay(1);
        HAL_GPIO_WritePin(ENTROPY_HCSR04_OUT_GRP, ENTROPY_HCSR04_OUT_PINNUM, GPIO_PIN_RESET);
        tmp = max_wait_time;
        do { // wait for signal assertion on ECHO pin
            start_time = __HAL_TIM_GET_COUNTER(htim);
            echo_state = HAL_GPIO_ReadPin(ENTROPY_HCSR04_IN_GRP, ENTROPY_HCSR04_IN_PINNUM);
            tmp--;
        } while (echo_state == GPIO_PIN_RESET && tmp > 0);
        if (tmp == 0) {
            return MQTT_RESP_TIMEOUT;
        }
        tmp = max_wait_time;
        do { // wait for signal de-assertion on ECHO pin
            tmp--;
            echo_state = HAL_GPIO_ReadPin(ENTROPY_HCSR04_IN_GRP, ENTROPY_HCSR04_IN_PINNUM);
            stop_time = __HAL_TIM_GET_COUNTER(htim);
        } while (echo_state == GPIO_PIN_SET && tmp > 0);
        if (tmp == 0) {
            return MQTT_RESP_TIMEOUT;
        }
        tmp = (stop_time < start_time) ? (htim->Init.Period - start_time + stop_time)
                                       : (stop_time - start_time);
        tmp &= XGET_BITMASK(nbits_grab);
        wr_idx = (idx * nbits_grab) >> 3;
        wr_offset = (idx * nbits_grab) % 8;
        if (prev_wr_idx != wr_idx) {
            out->data[wr_idx] = 0;
        }
        out->data[wr_idx] |= (tmp << wr_offset);
        prev_wr_idx = wr_idx;
    } // end of foop-loop statement
    return MQTT_RESP_OK;
} // end of mqttPlatformGetEntropy

mqttRespStatus mqttPlatformGetDateTime(mqttDateTime_t *out) {
    if (out == NULL) {
        return MQTT_RESP_ERRARGS;
    }
    HAL_StatusTypeDef status = HAL_OK;
    RTC_TimeTypeDef   sTime = {0};
    RTC_DateTypeDef   sDate = {0};
    status = HAL_RTC_GetTime(&hrtc, &sTime, RTC_FORMAT_BCD);
    if (status != HAL_OK) {
        goto done;
    }
    out->hour = sTime.Hours;
    out->minite = sTime.Minutes;
    out->second = sTime.Seconds;
    status = HAL_RTC_GetDate(&hrtc, &sDate, RTC_FORMAT_BCD);
    if (status != HAL_OK) {
        goto done;
    }
    out->month = sDate.Month;
    out->date = sDate.Date;
    out->year[1] = sDate.Year;
    out->year[0] = 0x20; // TODO : find better way to implement this
done:
    return (status == HAL_OK ? MQTT_RESP_OK : MQTT_RESP_ERR);
} // end of mqttPlatformGetDateTime

mqttRespStatus mqttPlatformInit(void) {
    HAL_StatusTypeDef status = HAL_OK;
    // MCU Configuration--------------------------------------------------------
    if (platform_stm32_hal_init_flag > 0) { // init count goes from 0x1 to 0x8
        STM32_HAL_periph_Deinit();
    } else {
        platform_stm32_hal_init_flag = 1;
        // Reset of all peripherals, Initializes the Flash interface and the Systick.
        status = HAL_Init();
        if (status == HAL_OK) {
            status = SystemClock_Config();
        }
    }
    // Configure peripherals that will be used in this MQTT implementation
    if (status == HAL_OK) {
        status = STM32_HAL_periph_Init();
    }
    if (status == HAL_OK) {
        status = STM32_HAL_RTC_Init();
    }
    if (status == HAL_OK) {
        status = STM32_HAL_GeneralTimer_Init(TICK_INT_PRIORITY);
    }
    return (status == HAL_OK ? MQTT_RESP_OK : MQTT_RESP_ERR);
} // end of mqttPlatformInit

mqttRespStatus mqttPlatformDeInit(void) { return MQTT_RESP_OK; }
