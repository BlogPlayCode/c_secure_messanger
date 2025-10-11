#!/bin/bash

# Простая кроссплатформенная версия
if command -v make >/dev/null 2>&1; then
    echo "Make found, proceeding with build..."
    
    # Удаляем старые файлы
    rm -f utility_cli.out utility_cli.exe
    
    # Сборка
    make
    
    # Очистка
    make clean
    
    # Устанавливаем права
    chmod +x utility_cli.out utility_cli.exe 2>/dev/null || true
else
    echo "Error: make command not found"
    exit 1
fi
