TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = XQAuthGateHook
XQAuthGateHook_FILES = Tweak.xm
XQAuthGateHook_CFLAGS = -fobjc-arc
XQAuthGateHook_FRAMEWORKS = Foundation UIKit
XQAuthGateHook_LIBRARIES = crypto

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 App"
