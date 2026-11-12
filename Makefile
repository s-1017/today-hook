TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

THEOS_USE_SUBSTRATE = 0
export THEOS_USE_SUBSTRATE

TWEAK_NAME = XQAuthGateHook
XQAuthGateHook_FILES = Tweak.xm
XQAuthGateHook_CFLAGS = -fobjc-arc
XQAuthGateHook_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 App"
