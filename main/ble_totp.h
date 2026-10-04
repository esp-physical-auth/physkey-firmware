#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_DEVICE_NAME "ATRI-TOTP" /* BLE 广播名，主人可以改 */

void ble_totp_start(void);

/* 处理一行命令（供 BLE 与串口共用）。line 可含可无结尾换行。 */
void ble_totp_handle_line(char *line);

/* 串口命令通道初始化：起一个任务读 USB-Serial/JTAG 输入，喂给 handle_line。 */
void ble_totp_start_console(void);

#ifdef __cplusplus
}
#endif
