#!/bin/sh
codesign --remove-signature ./chillnet_macos_aarch64_patch
codesign --timestamp --options=runtime -s "MyCert" ./chillnet_macos_aarch64_patch
