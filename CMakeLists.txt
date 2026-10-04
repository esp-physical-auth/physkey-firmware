cmake_minimum_required(VERSION 3.16)

# 目标芯片为 ESP32-C5
set(IDF_TARGET "esp32c5")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32c5-totp)
