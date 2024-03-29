/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32g0xx_hal.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

void HAL_TIM_MspPostInit(TIM_HandleTypeDef *htim);

/* Exported functions prototypes ---------------------------------------------*/
void Error_Handler(void);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
#define RADIO_INT_Pin GPIO_PIN_0
#define RADIO_INT_GPIO_Port GPIOA
#define RADIO_INT_EXTI_IRQn EXTI0_1_IRQn
#define RADIO_CS_Pin GPIO_PIN_7
#define RADIO_CS_GPIO_Port GPIOA
#define RADIO_RESET_Pin GPIO_PIN_4
#define RADIO_RESET_GPIO_Port GPIOC
#define PAIR_Pin GPIO_PIN_13
#define PAIR_GPIO_Port GPIOB
#define PAIR_EXTI_IRQn EXTI4_15_IRQn
#define VIBE_PWM_Pin GPIO_PIN_8
#define VIBE_PWM_GPIO_Port GPIOA
#define VIBE_BUTTON_Pin GPIO_PIN_8
#define VIBE_BUTTON_GPIO_Port GPIOB
#define VIBE_BUTTON_EXTI_IRQn EXTI4_15_IRQn
#define LED1_Pin GPIO_PIN_9
#define LED1_GPIO_Port GPIOB
#define LED2_Pin GPIO_PIN_10
#define LED2_GPIO_Port GPIOC
/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
