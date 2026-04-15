REPO_URL  := https://github.com/cpholguera/mas-app-android
DIST_DIR  := $(CURDIR)/dist

ifdef TARGET_APP
  _APP_ABS := $(realpath $(CURDIR)/$(TARGET_APP))

  ifeq ($(filter $(CURDIR)/%,$(_APP_ABS)),)
    $(error TARGET_APP "$(TARGET_APP)" must be a directory inside $(CURDIR))
  endif

  APP_ID    := $(subst -,_,$(TARGET_APP)).frooky.target.app
  BUILD_DIR := $(_APP_ABS)/build
  CLONE_DIR := $(BUILD_DIR)/mas-app-android
  APK_SRC   := $(CLONE_DIR)/app/build/outputs/apk/debug/app-debug.apk
  APK_DST   := $(DIST_DIR)/$(TARGET_APP).apk
endif

JAVA_HOME ?= $(shell java -XshowSettings:property -version 2>&1 | grep java.home | awk '{print $$3}')

BUNDLE_ID := org.owasp.mastestapp

ALL_APPS := $(shell find . -maxdepth 1 -mindepth 1 -type d \
	! -name dist ! -name '.*' \
	-exec basename {} \;)

.PHONY: build build-all install install-all uninstall uninstall-all clean clean-all

build: $(BUILD_DIR) $(DIST_DIR)
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make build TARGET_APP=<name>"; exit 1; }

	@if [ ! -d "$(CLONE_DIR)/.git" ]; then \
		git clone $(REPO_URL) $(CLONE_DIR); \
	else \
		echo "Repo already cloned, skipping git clone."; \
	fi

	@[ -n "$(TARGET_APP)" ] && \
		perl -i -pe 's|applicationId = "org.owasp.mastestapp"|applicationId = "$(APP_ID)"|' \
			"$(CLONE_DIR)/app/build.gradle.kts" && \
		echo "Set applicationId to $(APP_ID)" || true

	@[ -f "$(TARGET_APP)/MastgTest.kt" ] && \
		cp -f "$(TARGET_APP)/MastgTest.kt" \
			"$(CLONE_DIR)/app/src/main/java/org/owasp/mastestapp/MastgTest.kt" && \
		echo "Copied MastgTest.kt" || true

	@[ -f "$(TARGET_APP)/build.gradle.kts.libs" ] && \
		perl -i -pe "s|// ADD_LIBS_HERE|$$(cat "$(TARGET_APP)/build.gradle.kts.libs")|" \
			"$(CLONE_DIR)/app/build.gradle.kts" && \
		echo "Replaced libs in build.gradle.kts" || true

	@[ -f "$(TARGET_APP)/AndroidManifest.xml" ] && \
			cp "$(TARGET_APP)/AndroidManifest.xml" "$(CLONE_DIR)/app/src/main/AndroidManifest.xml" && \
			echo "Replaced AndroidManifest.xml" || true

	@[ -f "$(CLONE_DIR)/app/src/main/res/values/strings.xml" ] && \
			perl -i -pe "s|<string name=\"app_name\">MASTestApp</string>|<string name=\"app_name\">frooky: $(TARGET_APP)</string>|" \
					"$(CLONE_DIR)/app/src/main/res/values/strings.xml" && \
			echo "Replaced app_name in strings.xml" || true

	cd $(CLONE_DIR) && JAVA_HOME="$(JAVA_HOME)" ./gradlew assembleDebug
	mv $(APK_SRC) $(APK_DST)
	@echo "APK available at: $(APK_DST)"

build-all:
	@for app in $(ALL_APPS); do \
		echo "=== Building $$app ==="; \
		$(MAKE) build TARGET_APP=$$app; \
	done

install:
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make install TARGET_APP=<name> where <name> is the folder name the MAS DEMO compatible test app is."; exit 1; }
	adb install -r "$(APK_DST)"

install-all:
	@for app in $(ALL_APPS); do \
		echo "=== Installing $$app ==="; \
		$(MAKE) install TARGET_APP=$$app; \
	done

uninstall:
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make uninstall TARGET_APP=<name> where <name> is the folder name the MAS DEMO compatible test app is."; exit 1; }
	adb uninstall "$(APP_ID)"

uninstall-all:
	@for app in $(ALL_APPS); do \
		echo "=== Uninstalling $$app ==="; \
		$(MAKE) uninstall TARGET_APP=$$app; \
	done

clean:
	@[ -n "$(TARGET_APP)" ] || { echo "ERROR: TARGET_APP is required. Usage: make clean TARGET_APP=<name> where <name> is the folder name the MAS DEMO compatible test app is."; exit 1; }
	rm -rf $(BUILD_DIR)

clean-all:
	@for app in $(ALL_APPS); do \
		echo "=== Cleaning $$app ==="; \
		$(MAKE) clean TARGET_APP=$$app; \
	done
	rm -rf $(DIST_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)
