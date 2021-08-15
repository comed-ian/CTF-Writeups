#!/bin/sh
gdb attach $(ps aux | awk '{print $2}' | sed '5q;d')
